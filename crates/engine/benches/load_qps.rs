//! Multi-core, multi-connection wall-clock QPS bench for the load hot path.
//!
//! Unlike `crates/dns/benches/per_query.rs` (single buffer, alloc-count only,
//! can't see cross-core contention), this drives the real
//! `wiresurge_engine::load::run_load` path: one shared `WorkSource` hands a
//! `DnsRequest` to many actors on many cores at once. A regression that
//! reintroduces a shared per-query atomic refcount (PR #8 / 8ff5f9e) shows up
//! here as a wall-clock QPS collapse on a 1-row corpus (every query clones the
//! one shared buffer -> one cache line ping-pongs across cores) versus a
//! many-row corpus (the clones spread across many buffers / cache lines).
//!
//! Run with: `cargo bench -p wiresurge-engine --bench load_qps`. `harness = false`,
//! so `main` drives it directly (no libtest/criterion). Zero new dependencies.

use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use wiresurge_corpus::Corpus;
use wiresurge_engine::load::{LoadConfig, LoadProto, LoadStats, run_load};
use wiresurge_transport::ConnectTarget;

/// Zero-delay UDP echo: flip the QR/RA bits and send straight back inline (no
/// per-packet task spawn) so the server never becomes the bottleneck and the
/// client-side `WorkSource` clone is what's under test. A couple of reader tasks
/// share the socket for throughput.
async fn spawn_udp_echo() -> SocketAddr {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    for _ in 0..2 {
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let (n, peer) = match socket.recv_from(&mut buf).await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                if n >= 4 {
                    // Set the response bit so parse_response_header accepts it.
                    buf[2] = 0x81;
                    buf[3] = 0x80;
                }
                let _ = socket.send_to(&buf[..n], peer).await;
            }
        });
    }
    addr
}

/// Build a many-row corpus on disk (there is no in-memory many-row constructor;
/// `Corpus` exposes only `single`/`load`). Names are valid DNS so `build_query`
/// does not error before the run clock.
fn write_many_corpus(rows: usize) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "wiresurge-bench-corpus-{}-{}.txt",
        std::process::id(),
        rows
    ));
    let mut file = std::fs::File::create(&path).unwrap();
    for i in 0..rows {
        writeln!(file, "q{i}.example.com").unwrap();
    }
    path
}

fn make_cfg(addr: SocketAddr, corpus: Arc<Corpus>, concurrency: usize, count: u64) -> LoadConfig {
    LoadConfig {
        proto: LoadProto::Do53Udp,
        target: ConnectTarget::new(addr),
        corpus,
        qtype: 1,
        concurrency,
        in_flight: 256,
        timeout: Duration::from_secs(5),
        qps_cap: None,
        duration: None,
        count: Some(count),
        randomize: false,
        seed: 0,
        edns_options: Vec::new(),
    }
}

async fn run(addr: SocketAddr, corpus: Arc<Corpus>, threads: usize, count: u64) -> LoadStats {
    run_load(make_cfg(addr, corpus, threads, count), CancellationToken::new())
        .await
        .unwrap()
}

fn main() {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let addr = spawn_udp_echo().await;

        // Warm up (connect/JIT), discard.
        let _ = run(addr, Corpus::single("example.com"), threads, 50_000).await;

        let n = 2_000_000;
        let one = run(addr, Corpus::single("example.com"), threads, n).await;

        let path = write_many_corpus(4096);
        let many = run(addr, Corpus::load(&path).unwrap(), threads, n).await;
        let _ = std::fs::remove_file(&path);

        println!("== multi-core load QPS bench (threads={threads}) ==");
        println!(
            "corpus_1row   {:>12.0} recv_qps  {:>8.3}s",
            one.recv_qps(),
            one.duration_s
        );
        println!(
            "corpus_many   {:>12.0} recv_qps  {:>8.3}s",
            many.recv_qps(),
            many.duration_s
        );
        println!("ratio 1row/many {:>6.3}", one.recv_qps() / many.recv_qps());

        // Loose guard: only a large (2x+) collapse — the PR #8 contention
        // signature — fails; loopback micro-noise does not.
        assert!(
            one.recv_qps() > many.recv_qps() * 0.5,
            "1-row QPS collapsed vs many-row corpus — shared cache-line contention regression"
        );
    });
}
