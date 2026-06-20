# WireSurge Dependency Policy

WireSurge uses established libraries for protocol parsing, cryptography, async I/O, serialization, storage, and other security-sensitive or standards-heavy work. It does not add a library merely to avoid writing a small, well-contained helper.

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
