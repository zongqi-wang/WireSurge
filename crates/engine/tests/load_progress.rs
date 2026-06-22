use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use wiresurge_corpus::Corpus;
use wiresurge_engine::load::{
    LoadConfig, LoadProto, ProgressConfig, run_load, run_load_with_progress,
};
use wiresurge_metrics::RunSnapshot;
use wiresurge_transport::ConnectTarget;

async fn spawn_echo() -> SocketAddr {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, peer) = match socket.recv_from(&mut buf).await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let mut response = buf[..n].to_vec();
            response[2] = 0x81;
            response[3] = 0x80;
            let _ = socket.send_to(&response, peer).await;
        }
    });
    addr
}

fn config(
    addr: SocketAddr,
    concurrency: usize,
    count: Option<u64>,
    duration: Option<Duration>,
) -> LoadConfig {
    LoadConfig {
        proto: LoadProto::Do53Udp,
        target: ConnectTarget::new(addr),
        corpus: Corpus::single("example.com"),
        qtype: 1,
        concurrency,
        in_flight: 32,
        timeout: Duration::from_secs(2),
        qps_cap: None,
        duration,
        count,
        randomize: false,
        seed: 0,
        edns_option: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retains_per_worker_stats() {
    let addr = spawn_echo().await;
    let stats = run_load(config(addr, 3, Some(900), None), CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(stats.workers.len(), 3);
    let worker_qps: f64 = stats.workers.iter().map(|w| w.qps).sum();
    let aggregate_qps = stats.recorder.sent as f64 / stats.duration_s;
    assert!((worker_qps - aggregate_qps).abs() < aggregate_qps * 0.01 + 1.0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn emits_live_then_final_snapshot() {
    let addr = spawn_echo().await;
    let (tx, mut rx) = tokio::sync::watch::channel(RunSnapshot::default());
    let cancel = CancellationToken::new();

    let collector = tokio::spawn(async move {
        let mut live = 0usize;
        let mut saw_final = false;
        let mut worker_counts = Vec::new();
        while rx.changed().await.is_ok() {
            let snap = rx.borrow().clone();
            if snap.elapsed_s == 0.0 && !snap.final_sample {
                continue;
            }
            worker_counts.push(snap.workers.len());
            if snap.final_sample {
                saw_final = true;
            } else {
                live += 1;
            }
        }
        (live, saw_final, worker_counts)
    });

    let stats = run_load_with_progress(
        config(addr, 2, None, Some(Duration::from_millis(350))),
        cancel,
        Some((
            ProgressConfig {
                interval: Duration::from_millis(50),
            },
            tx,
        )),
    )
    .await
    .unwrap();

    let (live, saw_final, worker_counts) = collector.await.unwrap();
    // The watch channel keeps only the latest value, so a load-starved collector
    // may observe fewer distinct frames than were sent; one live frame is enough
    // to prove sampling ran without making the count host-load-dependent.
    assert!(live >= 1, "expected at least 1 live tick, got {live}");
    assert!(saw_final, "expected a final snapshot");
    assert!(
        worker_counts.iter().all(|&n| n == 2),
        "every snapshot has all workers: {worker_counts:?}"
    );
    assert_eq!(stats.workers.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_progress_matches_progress_counts() {
    let addr = spawn_echo().await;
    let plain = run_load(config(addr, 2, Some(500), None), CancellationToken::new())
        .await
        .unwrap();

    let (tx, _rx) = tokio::sync::watch::channel(RunSnapshot::default());
    let withp = run_load_with_progress(
        config(addr, 2, Some(500), None),
        CancellationToken::new(),
        Some((
            ProgressConfig {
                interval: Duration::from_millis(50),
            },
            tx,
        )),
    )
    .await
    .unwrap();

    assert_eq!(plain.recorder.sent, withp.recorder.sent);
    assert_eq!(plain.recorder.received, withp.recorder.received);
    assert_eq!(plain.recorder.errors, withp.recorder.errors);
}
