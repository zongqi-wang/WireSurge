# Dependency Policy

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

WireSurge uses `domain = 0.12.1` from NLnet Labs with only the `std` feature. The stable base message builder/parser and EDNS option types replace WireSurge's handwritten DNS codec. WireSurge continues to own UDP/TCP sockets, connection reuse, pacing, cancellation, and metrics.

The `net`, `resolv`, and `unstable-*` features are not enabled. NLnet Labs currently labels its client/server transport work experimental, and those transports would also obscure behavior the load engine needs to control.

`hickory-proto` remains a valid alternative if a future requirement materially benefits from its transport implementation. It is not included now because its protocol-only graph pulls substantially more transitive crates, including IDNA/ICU support. WireSurge must not carry both DNS stacks without a specific interoperability requirement and benchmark.

## CLI Decision

WireSurge uses `clap = 4.6.1` with default features disabled and an explicit feature allowlist: Clap's default set (`std`, `color`, `help`, `usage`, `error-context`, `suggestions`) plus `derive` and `wrap_help`. This matches the default graph today, so its only benefit is review control — a future Clap release cannot add a new default feature without a manifest change and dependency review. The `env` feature is intentionally omitted so flags never read ambient environment variables implicitly.

`clap` owns top-level command parsing, option parsing, typed value conversion, help, and generic argument validation. WireSurge maps its parse errors into the existing structured error envelope when `--output json` is selected. Domain-specific parsing remains in the owning crate so stable codes such as `invalid_dns_transport` and `invalid_dns_qtype` do not become generic CLI errors.

The current CLI still represents `workspace`, `request`, `runner`, and `report` actions as strings and validates them in command handlers. This is transitional implementation debt. Those action sets should become nested Clap `Subcommand` enums so Clap owns their help, allowed values, and required arguments as well.

## Known Replacement Work

The initial scaffold predates the library-first tenet in several areas. Before those areas grow, replace them through reviewed dependency decisions:

- custom JSON/JSONC and YAML parsing in `crates/core`;
- custom HTTP/1.1 wire construction and response parsing in `crates/http`;
- string-based nested CLI action parsing and validation in `crates/cli`;
- direct platform signal bindings and the synchronous transport runtime;
- custom latency histogram implementation in `crates/dns`.

Each replacement must preserve WireSurge's stable schemas, structured errors, connection ownership, pacing behavior, cancellation semantics, and bounded-memory metrics.
