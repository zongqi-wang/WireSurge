# ADR 0001 — rustls with the `ring` crypto provider

Status: accepted
Date: 2026-06-20

## Context

DoT and DoH need TLS. The dependency policy (`docs/dependency-policy.md`) says
use an established crate over a hand-rolled one, so the choice is which TLS
stack, not whether to build one. `rustls` is the established pure-Rust option
and integrates with `tokio` through `tokio-rustls`; it requires a crypto
provider. The two supported providers are `ring` and `aws-lc-rs`.

## Decision

Use `rustls` with the **`ring`** provider, selected explicitly via
`ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider())`
rather than relying on a process-default provider. Pinned, default features
off:

- `rustls = "=0.23.35"` features `std`, `ring`, `tls12`
- `tokio-rustls = "=0.26.4"` features `ring`, `logging`, `tls12`
- `rustls-native-certs = "=0.8.2"` for the OS trust-store root set

`ServerName` is used through the `rustls` re-export, so `rustls-pki-types` is a
transitive dependency rather than a direct one.

`tls12` is enabled because the target CoreDNS `customtls` listener may not offer
TLS 1.3.

## Why `ring` over `aws-lc-rs`

- `aws-lc-rs` builds its C/assembly core through `cmake`/`bindgen`, which needs
  a working C toolchain on the build host. The Stage 9 plan builds the load
  binary **natively on the Graviton load-gen box** (no cross toolchain on this
  Mac); `ring` builds with the Rust toolchain alone and is known to compile
  clean on `aarch64-unknown-linux-musl`, avoiding a second native-build ADR.
- `ring` keeps the dependency tree smaller (no `cmake`/`bindgen`/`cc` chain),
  which keeps `cargo-deny` duplicate auditing tractable.
- Throughput is not crypto-bound at the 20k-QPS target on Graviton4; the
  pod/NLB is the ceiling, so `aws-lc-rs`'s raw-crypto edge buys nothing here.

If a future FIPS requirement appears, revisit — `aws-lc-rs` has a FIPS module
and this decision would be reopened.

## Consequences

- `ring` is licensed under a mix that includes ISC and OpenSSL-style terms, and
  pulls `untrusted` (ISC). `deny.toml`'s license allowlist gains `ISC` and the
  relevant OpenSSL-family entries so the `licenses` gate passes at
  `confidence-threshold = 0.93`. Each added license is auditable here.
- One TLS stack only: we use our own `tokio-rustls` connector and drive
  `hyper::client::conn` over it (Stage 6). No `hyper-rustls`, so there is no
  second `rustls` version or duplicate provider in the tree. `cargo tree
  --duplicates` is gated in CI.
