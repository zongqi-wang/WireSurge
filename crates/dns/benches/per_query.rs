//! Per-query allocation/latency bench for the DNS hot path.
//!
//! These items are per-query *micro*-allocations, so the metric that matters is
//! **heap allocations per query**, not wall-clock (which loopback I/O dwarfs). A
//! counting global allocator records alloc count + bytes; each scenario snapshots
//! the delta around an N-query loop and divides by N.
//!
//! Run with: `cargo bench -p wiresurge-dns`. `harness = false`, so `main` drives
//! it directly (no libtest/criterion).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use wiresurge_dns::build_query;
use wiresurge_dns::transport::do53::TcpTransport;
use wiresurge_dns::transport::doh;
use wiresurge_dns::transport::{Connection, DnsRequest, Transport};
use wiresurge_transport::{ConnectTarget, HttpMethod, HttpTemplate};

/// Global allocator that counts every allocation routed through `System`.
struct CountingAlloc;

static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);
static ALLOC_BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
        ALLOC_BYTES.fetch_add(new_size, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

struct Counts {
    allocs: usize,
    bytes: usize,
}

fn snapshot() -> Counts {
    Counts {
        allocs: ALLOC_COUNT.load(Ordering::Relaxed),
        bytes: ALLOC_BYTES.load(Ordering::Relaxed),
    }
}

fn report(label: &str, before: Counts, after: Counts, elapsed: Duration, n: usize) {
    let allocs = after.allocs - before.allocs;
    let bytes = after.bytes - before.bytes;
    println!(
        "{label:<40} {:>8.2} allocs/query  {:>10.1} bytes/query  {:>8.0} ns/query",
        allocs as f64 / n as f64,
        bytes as f64 / n as f64,
        elapsed.as_nanos() as f64 / n as f64,
    );
}

fn wire() -> Arc<[u8]> {
    build_query(0, "example.com", 1, None).unwrap().into()
}

/// Scenario 1: DoH per-query request assembly (URI parse + body + headers), no
/// network. Isolates items A + B.
fn bench_doh_assembly(method: HttpMethod, label: &str, n: usize) {
    let template = HttpTemplate {
        method,
        base_uri: "https://dns.example.net/dns-query".to_string(),
        query: "token=abcdef0123456789".to_string(),
    };
    let prepared = doh::Prepared::from_template(&template).unwrap();
    let wire = wire();

    // Warm up (first call may grow lazily-initialized statics).
    let _ = doh::assemble(&prepared, &wire).unwrap();

    let before = snapshot();
    let start = Instant::now();
    for _ in 0..n {
        let (uri, body) = doh::assemble(&prepared, &wire).unwrap();
        std::hint::black_box((&uri, &body));
    }
    let elapsed = start.elapsed();
    report(label, before, snapshot(), elapsed, n);
}

/// Scenario 2: framed TCP exchange over loopback. Yardstick for item C.
async fn bench_framed_tcp(n: usize, in_flight: usize) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Echo server: read length-prefixed query, set the response bit, echo back.
    tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 65535];
        loop {
            let mut len_buf = [0u8; 2];
            if tcp.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            if tcp.read_exact(&mut buf[..len]).await.is_err() {
                break;
            }
            buf[2] = 0x81;
            buf[3] = 0x80;
            let mut frame = Vec::with_capacity(len + 2);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
            frame.extend_from_slice(&buf[..len]);
            if tcp.write_all(&frame).await.is_err() {
                break;
            }
            let _ = tcp.flush().await;
        }
    });

    let conn = TcpTransport::connect(ConnectTarget::new(addr)).await.unwrap();
    let wire = wire();
    let req = || DnsRequest { wire: Arc::clone(&wire) };

    // Warm up the connection + reader buffer.
    conn.exchange(req(), Duration::from_secs(5)).await.unwrap();

    let before = snapshot();
    let start = Instant::now();
    let mut sent = 0usize;
    while sent < n {
        let batch = in_flight.min(n - sent);
        let mut inflight = futures_util::stream::FuturesUnordered::new();
        for _ in 0..batch {
            inflight.push(conn.exchange(req(), Duration::from_secs(5)));
        }
        use futures_util::StreamExt;
        while let Some(r) = inflight.next().await {
            r.unwrap();
        }
        sent += batch;
    }
    let elapsed = start.elapsed();
    report("framed_tcp_exchange", before, snapshot(), elapsed, n);
}

fn main() {
    println!("== per-query hot-path allocation bench ==");
    let n = 200_000;
    bench_doh_assembly(HttpMethod::Get, "doh_assembly_get", n);
    bench_doh_assembly(HttpMethod::Post, "doh_assembly_post", n);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(bench_framed_tcp(100_000, 64));
}
