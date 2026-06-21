# References

These projects and specifications inform the steering architecture. A reference is not automatically a selected dependency.

## Product and Runtime

- [Yaak](https://github.com/mountain-loop/yaak): local-first API client reference for Tauri, Rust, React, filesystem workspaces, environments, and plugins.
- [DNS-OARC Flamethrower](https://github.com/DNS-OARC/flamethrower): DNS performance and functional-testing reference.
- [Rust target platform support](https://doc.rust-lang.org/rustc/platform-support.html): release target tiers.
- [Tokio runtime builder](https://docs.rs/tokio/latest/tokio/runtime/struct.Builder.html): bounded worker-thread configuration.
- [Tokio signals](https://docs.rs/tokio/latest/tokio/signal/): asynchronous platform signal integration.
- [Tokio `CancellationToken`](https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html): hierarchical cooperative cancellation.
- [Hyper HTTP/2 client connection](https://docs.rs/hyper/latest/hyper/client/conn/http2/index.html): low-level connection driver used for DoH.

## Protocols and Dependencies

- [Hickory Proto](https://docs.rs/hickory-proto/latest/hickory_proto/): selected DNS message, name, record type, and EDNS0 primitives.
- [Hickory Net](https://docs.rs/hickory-net/latest/hickory_net/): candidate transport layer for a future DNS-over-QUIC stage (DoT and DoH ship on `rustls`/`ring`).
- [NLnet Labs `domain`](https://github.com/NLnetLabs/domain): reviewed protocol-first alternative.
- [`clap`](https://docs.rs/clap/latest/clap/): selected command-line parser and help system.
- [Serde](https://serde.rs/): selected typed serialization framework.
- [`yaml_serde`](https://docs.rs/yaml_serde/latest/yaml_serde/): selected maintained YAML adapter.
- [`hdrhistogram`](https://docs.rs/hdrhistogram/latest/hdrhistogram/): selected bounded latency histogram.
- [PROXY protocol specification](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt): connection metadata framing.
- [RFC 6066](https://datatracker.ietf.org/doc/html/rfc6066): TLS extensions including SNI.
- [RFC 6891](https://datatracker.ietf.org/doc/html/rfc6891): EDNS0 and the OPT pseudo-RR.
- [RFC 8926](https://datatracker.ietf.org/doc/html/rfc8926): Geneve encapsulation.
- [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny): advisory, license, duplicate, and source-policy enforcement.

## Documentation

- [mdBook](https://rust-lang.github.io/mdBook/): the Rust project documentation system used to render this book.
- [GitHub Pages custom workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages): build-artifact deployment model.
