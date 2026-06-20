# WireSurge Dependency Policy

WireSurge uses established first-party or third-party libraries for protocol parsing, cryptography, async I/O, signals, serialization, CLI parsing, storage, histograms, and other security-sensitive or standards-heavy work. It does not add a library merely to avoid writing a small, well-contained helper.

A handrolled parser, protocol codec, argument scanner, histogram, or cryptographic implementation is presumed to be replacement work unless an architecture decision record explains why an established library cannot satisfy the requirement. WireSurge-owned code should concentrate on scheduling, pacing, connection lifecycle, cancellation policy, workflow semantics, and metrics semantics.

## Admission Rules

Every new external crate requires a review of:

1. Maintainer identity, release history, security policy, and unresolved advisories.
2. License compatibility and minimum supported Rust version.
3. Enabled features, transitive dependency count, duplicate versions, build scripts, native code, and `unsafe` usage.
4. Whether a narrower crate or module provides the required API.
5. Whether the dependency owns a protocol concern or would take ownership away from WireSurge's scheduler, connection managers, cancellation, or metrics.

Direct external dependencies are declared once in `[workspace.dependencies]`, pinned to an exact reviewed version, and consumed with `workspace = true`. Default features are disabled unless their inclusion is documented. `Cargo.lock` is committed and release builds use `--locked`.

Git dependencies are denied by default. An exception requires an immutable commit revision, a written reason, and a removal plan. Dependencies containing native code, build scripts, bundled executables, or new cryptographic implementations require an architecture decision record.

## Automated Controls

- `cargo deny check` rejects known vulnerabilities, yanked direct dependencies, unapproved licenses and sources, wildcard versions, and duplicate crate versions.
- `cargo tree --duplicates` is reviewed when dependencies change.
- CI actions are pinned to immutable commit SHAs.
- Dependency updates are isolated in reviewable pull requests; feature and transitive graph changes are part of the review.
- Release automation will add an SBOM, checksums, and reproducible `--locked` builds before public binaries are shipped.

## DNS Decision

WireSurge uses `hickory-proto = 0.26.1` with only its `std` feature. Hickory owns DNS names, record types, full-message encoding and decoding, EDNS options, extended response codes, and question parsing. WireSurge validates the response transaction ID, message type, opcode, echoed question, query class, and query type before recording a response.

WireSurge retains its Tokio UDP/TCP loops because the load engine needs one socket or connection per worker, explicit QPS pacing, request deadlines, late-datagram filtering, cancellation, and metrics ownership. `hickory-net` is the preferred future candidate for DoT, DoH, DoQ, and other encrypted transports; it is not used for current UDP/TCP execution because its higher-level exchange model would duplicate or obscure those controls.

NLnet Labs `domain` remains a credible narrower alternative. It has a lean protocol-first design, supports no-std use cases, and avoids coupling to an async runtime. Hickory was selected because its complete `Message` model makes response validation direct and because its protocol types align with the Hickory networking stack planned for encrypted DNS. WireSurge must not carry both DNS protocol stacks without a specific interoperability requirement and benchmark.

## Serialization Decision

WireSurge uses `serde = 1.0.228`, `serde_json = 1.0.150`, `yaml_serde = 0.10.4`, and `serde_path_to_error = 0.1.20`. Serde owns typed JSON/YAML conversion; path-aware errors are mapped into the stable `WireSurgeError` envelope. `yaml_serde` is the YAML organization's maintained fork of the discontinued `serde_yaml` crate. Default features are disabled; Serde, JSON, and URL handling explicitly enable only their required `std` support plus Serde derives.

Serialization failures are propagated instead of being hidden behind string concatenation. Request bodies remain opaque strings, unknown JSON syntax is rejected by the standards-compliant parser, and redaction is applied through separate output views so persisted request files retain their original values.

## Runtime and HTTP Decision

WireSurge uses `tokio = 1.52.3` and `tokio-util = 0.7.18` for async sockets, timers, tasks, signals, and cancellation tokens. The CLI owns one multithread runtime; DNS workers are tasks rather than OS threads. Ctrl-C and SIGTERM enter the same cancellation path without direct platform FFI.

HTTP uses `hyper = 1.10.1`, `hyper-util = 0.1.20`, `http-body-util = 0.1.3`, `hyper-rustls = 0.27.9`, and `url = 2.5.8`. Hyper owns HTTP/1.1 and HTTP/2 framing, body decoding, and reusable connection pools. Rustls provides HTTPS without a mandatory system OpenSSL dependency. Native trust roots, HTTP/1.1, HTTP/2, TLS 1.2/1.3, and the `ring` provider are explicit features; redirects remain disabled so WireSurge does not silently rewrite methods, bodies, or credentials.

The `ring` provider contains native assembly and a build script. It is accepted here because audited TLS requires a supported rustls cryptography provider, it does not introduce a runtime system-library dependency, and it supports the project's release targets. The decision and removal conditions are recorded in [ADR 0001](adr/0001-dependency-backed-protocol-runtime.md).

## Metrics Decision

WireSurge uses `hdrhistogram = 7.5.4` with default features disabled. Per-worker histograms record microseconds over a fixed one-microsecond to one-hour range with three significant digits, merge without replaying samples, and expose out-of-range counts rather than silently saturating them.

## CLI Decision

WireSurge uses `clap = 4.6.1` with default features disabled and an explicit feature allowlist. In this version, `std`, `color`, `help`, `usage`, `error-context`, and `suggestions` are exactly Clap's default feature set; WireSurge additionally enables `derive` and `wrap_help`. The current declaration therefore does not reduce the dependency graph compared with enabling defaults and adding those two features. Its benefit is review control: a future Clap release cannot add a new default feature to WireSurge without a manifest change and dependency review.

The `env` feature is not part of Clap's defaults and remains intentionally omitted so flags do not read ambient environment variables implicitly. If explicit feature allowlisting stops being a project requirement, the simpler equivalent declaration is to enable Clap defaults and request only `derive` and `wrap_help`.

`clap` owns top-level command parsing, option parsing, typed value conversion, help, and generic argument validation. WireSurge maps its parse errors into the existing structured error envelope when `--output json` is selected. Domain-specific parsing remains in the owning crate so stable codes such as `invalid_dns_transport` and `invalid_dns_qtype` do not become generic CLI errors.

The current CLI still represents `workspace`, `request`, `runner`, and `report` actions as strings and validates them in command handlers. This is transitional implementation debt. Those action sets should become nested Clap `Subcommand` enums so Clap owns their help, allowed values, and required arguments as well.

## Completed Replacement Work

The initial scaffold's standards-heavy replacements are complete:

- Serde replaces custom JSON/JSONC and YAML parsing in `crates/core`;
- Hyper and rustls replace custom HTTP/1.1 construction and response parsing in `crates/http`;
- Tokio signals, tasks, sockets, timers, and cancellation replace direct signal bindings and synchronous transports;
- `hdrhistogram` replaces the custom DNS latency histogram;
- `hickory-proto` replaces NLnet Labs `domain` for DNS message semantics.

Each replacement must preserve WireSurge's stable schemas, structured errors, connection ownership, pacing behavior, cancellation semantics, and bounded-memory metrics.
