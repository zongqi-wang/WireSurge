# References

These projects and specifications inform the steering architecture. A reference is not automatically a selected dependency; selections are recorded in the [Dependency Policy](dependency-policy.md) or an architecture decision record.

## Product and Runtime

- [Yaak](https://github.com/mountain-loop/yaak): local-first API client reference for Tauri, Rust, React, filesystem workspaces, environments, and plugins.
- [DNS-OARC Flamethrower](https://github.com/DNS-OARC/flamethrower): DNS performance and functional-testing reference.
- [Rust target platform support](https://doc.rust-lang.org/rustc/platform-support.html): release target tiers.
- [Tokio runtime builder](https://docs.rs/tokio/latest/tokio/runtime/struct.Builder.html): bounded worker-thread configuration.
- [Tokio signals](https://docs.rs/tokio/latest/tokio/signal/): asynchronous platform signal integration.
- [Tokio `CancellationToken`](https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html): hierarchical cooperative cancellation.
- [Hyper client](https://docs.rs/hyper-util/latest/hyper_util/client/legacy/struct.Client.html): reusable connection pools.

## Protocols and Dependencies

- [NLnet Labs `domain`](https://github.com/NLnetLabs/domain): selected DNS message, name, record type, and EDNS0 primitives.
- [`clap`](https://docs.rs/clap/latest/clap/): selected command-line parser and help system.
- [Hickory DNS](https://github.com/hickory-dns/hickory-dns): DNS alternative if a future transport requirement justifies its broader graph.
- [PROXY protocol specification](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt): connection metadata framing.
- [RFC 6066](https://datatracker.ietf.org/doc/html/rfc6066): TLS extensions including SNI.
- [RFC 6891](https://datatracker.ietf.org/doc/html/rfc6891): EDNS0 and the OPT pseudo-RR.
- [RFC 8926](https://datatracker.ietf.org/doc/html/rfc8926): Geneve encapsulation.
- [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny): advisory, license, duplicate, and source-policy enforcement.

## Documentation

- [mdBook](https://rust-lang.github.io/mdBook/): the Rust project documentation system used to render this book.
- [GitHub Pages custom workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages): build-artifact deployment model.
