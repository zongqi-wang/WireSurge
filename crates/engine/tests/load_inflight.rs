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
        edns_options: Vec::new(),
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
        edns_options: Vec::new(),
    };
    let stats = run_load(config, CancellationToken::new()).await.unwrap();
    assert!(stats.recorder.received > 0);
    assert!(stats.duration_s >= 0.3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancel_before_connect_returns_promptly_as_conn_error() {
    let config = LoadConfig {
        proto: LoadProto::Do53Tcp,
        target: ConnectTarget::new("10.255.255.1:53".parse().unwrap()),
        corpus: Corpus::single("example.com"),
        qtype: 1,
        concurrency: 4,
        in_flight: 8,
        timeout: Duration::from_secs(30),
        qps_cap: None,
        duration: None,
        count: Some(1000),
        randomize: false,
        seed: 0,
        edns_options: Vec::new(),
    };
    let cancel = CancellationToken::new();
    cancel.cancel();
    let started = std::time::Instant::now();
    let stats = run_load(config, cancel).await.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "cancelled run must not block on connect"
    );
    assert_eq!(
        stats.recorder.conn_errors, 4,
        "each actor records a conn error"
    );
    assert!(stats.cancelled);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "depends on a black-hole address (SYN never answered); network-dependent timing"]
async fn connect_timeout_bounds_a_black_hole_target() {
    let config = LoadConfig {
        proto: LoadProto::Do53Tcp,
        target: ConnectTarget::new("10.255.255.1:53".parse().unwrap()),
        corpus: Corpus::single("example.com"),
        qtype: 1,
        concurrency: 2,
        in_flight: 4,
        timeout: Duration::from_millis(200),
        qps_cap: None,
        duration: None,
        count: Some(10),
        randomize: false,
        seed: 0,
        edns_options: Vec::new(),
    };
    let started = std::time::Instant::now();
    let stats = run_load(config, CancellationToken::new()).await.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "connect must be bounded by the timeout, not the OS SYN timeout"
    );
    assert_eq!(
        stats.recorder.received, 0,
        "no query can succeed to a dead target"
    );
    assert!(
        stats.recorder.conn_errors > 0 || stats.recorder.errors > 0,
        "a dead target must surface as connection/transport errors"
    );
}
