use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use wiresurge_corpus::Corpus;
use wiresurge_engine::load::{LoadConfig, LoadProto, run_load};
use wiresurge_transport::ConnectTarget;

/// A UDP echo server that answers each query after a fixed per-request delay,
/// concurrently. With one query in flight throughput would be capped at
/// 1/delay; many in flight must beat that wall-clock bound by a wide margin.
async fn spawn_delayed_echo(delay: Duration) -> SocketAddr {
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
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = socket.send_to(&response, peer).await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_in_flight_beats_one_in_flight() {
    let delay = Duration::from_millis(20);
    let addr = spawn_delayed_echo(delay).await;

    let count = 2000u64;
    let config = LoadConfig {
        proto: LoadProto::Do53Udp,
        target: ConnectTarget::new(addr),
        corpus: Corpus::single("example.com"),
        qtype: 1,
        concurrency: 1,
        in_flight: 256,
        timeout: Duration::from_secs(2),
        qps_cap: None,
        duration: None,
        count: Some(count),
        randomize: false,
        seed: 0,
        token: None,
    };

    let started = std::time::Instant::now();
    let stats = run_load(config, CancellationToken::new()).await.unwrap();
    let elapsed = started.elapsed();

    assert_eq!(stats.recorder.sent, count);
    assert_eq!(stats.recorder.received, count);
    assert_eq!(stats.recorder.errors, 0);
    assert_eq!(stats.recorder.timeouts, 0);

    let serial_floor = delay.mul_f64(count as f64);
    assert!(
        elapsed < serial_floor / 10,
        "elapsed {elapsed:?} should be far below the one-in-flight floor {serial_floor:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duration_mode_stops_and_counts() {
    let addr = spawn_delayed_echo(Duration::from_millis(1)).await;
    let config = LoadConfig {
        proto: LoadProto::Do53Udp,
        target: ConnectTarget::new(addr),
        corpus: Corpus::single("example.com"),
        qtype: 1,
        concurrency: 2,
        in_flight: 64,
        timeout: Duration::from_secs(1),
        qps_cap: None,
        duration: Some(Duration::from_millis(300)),
        count: None,
        randomize: false,
        seed: 7,
        token: None,
    };
    let stats = run_load(config, CancellationToken::new()).await.unwrap();
    assert!(stats.recorder.received > 0);
    assert!(stats.duration_s >= 0.3);
}
