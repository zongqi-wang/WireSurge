//! End-to-end DoH smoke through the real `run_load` engine path: a loopback
//! rustls + HTTP/2 server answers each query after a fixed per-request delay,
//! and one connection with a deep in-flight window must beat the
//! one-in-flight wall-clock floor by a wide margin. This proves the engine
//! drives DoH multiplexing under load; it is a functional proof on loopback,
//! not an absolute QPS measurement against a real resolver.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::server::conn::http2 as server_http2;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use wiresurge_corpus::Corpus;
use wiresurge_engine::load::{LoadConfig, LoadProto, run_load};
use wiresurge_transport::{
    AppProto, ConnectTarget, HttpMethod, HttpTemplate, TlsParams, build_client_config,
};

const CERT_DER: &[u8] = include_bytes!("../../dns/tests/fixtures/cert.der");
const KEY_DER: &[u8] = include_bytes!("../../dns/tests/fixtures/key.der");
const DNS_MESSAGE: &str = "application/dns-message";

fn server_config() -> Arc<ServerConfig> {
    let cert = CertificateDer::from(CERT_DER.to_vec());
    let key = PrivateKeyDer::try_from(KEY_DER.to_vec()).unwrap();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

/// A DoH (POST) echo server that answers each query after `delay`, each on its
/// own task so many concurrent streams overlap instead of serializing.
async fn spawn_delayed_doh_echo(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config());
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = service_fn(move |request: Request<Incoming>| async move {
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    let mut wire = body.to_vec();
                    tokio::time::sleep(delay).await;
                    wire[2] = 0x81;
                    wire[3] = 0x80;
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, DNS_MESSAGE)
                            .body(Full::new(Bytes::from(wire)))
                            .unwrap(),
                    )
                });
                let _ = server_http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    addr
}

/// A DoH server that answers normally for `alive` then closes the connection,
/// modelling a peer GOAWAY / LB reset mid-run. Used to prove the engine stops
/// feeding a dead connection instead of hot-spinning through the whole count.
async fn spawn_dies_after(alive: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config());
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = service_fn(move |request: Request<Incoming>| async move {
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    let mut wire = body.to_vec();
                    wire[2] = 0x81;
                    wire[3] = 0x80;
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, DNS_MESSAGE)
                            .body(Full::new(Bytes::from(wire)))
                            .unwrap(),
                    )
                });
                let conn = server_http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service);
                // Drop the connection after `alive`, severing the client driver.
                let _ = tokio::time::timeout(alive, conn).await;
            });
        }
    });
    addr
}

fn doh_config(addr: SocketAddr, count: u64) -> LoadConfig {
    let tls = build_client_config(&TlsParams {
        proto: AppProto::Doh,
        insecure: true,
    })
    .unwrap();
    let target = ConnectTarget::new(addr)
        .with_tls(tls, AppProto::Doh, Some("localhost".to_string()), false)
        .with_http(HttpTemplate {
            method: HttpMethod::Post,
            base_uri: "https://localhost/dns-query".to_string(),
            query: String::new(),
        });
    LoadConfig {
        proto: LoadProto::Doh,
        target,
        corpus: Corpus::single("example.com"),
        qtype: 1,
        concurrency: 1,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_many_in_flight_beats_one_in_flight() {
    let delay = Duration::from_millis(20);
    let addr = spawn_delayed_doh_echo(delay).await;

    let count = 1000u64;
    let started = std::time::Instant::now();
    let stats = run_load(doh_config(addr, count), CancellationToken::new())
        .await
        .unwrap();
    let elapsed = started.elapsed();

    assert_eq!(stats.recorder.sent, count);
    assert_eq!(
        stats.recorder.received, count,
        "every DoH query must answer"
    );
    assert_eq!(stats.recorder.errors, 0);
    assert_eq!(stats.recorder.timeouts, 0);

    // One stream at a time would need count * delay; multiplexing must beat that
    // floor by a wide margin.
    let serial_floor = delay.mul_f64(count as f64);
    assert!(
        elapsed < serial_floor / 10,
        "elapsed {elapsed:?} should be far below the one-in-flight floor {serial_floor:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_dead_connection_does_not_busy_spin() {
    // Server dies ~150ms in. A huge count means a hot-spinning actor (issuing
    // doomed exchanges that fail synchronously) would drain the whole budget and
    // record millions of conn_errors. The is_closed() guard must stop it instead,
    // so it returns quickly with sent far below count.
    let addr = spawn_dies_after(Duration::from_millis(150)).await;
    let count = 50_000_000u64;

    let started = std::time::Instant::now();
    let stats = run_load(doh_config(addr, count), CancellationToken::new())
        .await
        .unwrap();
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(10),
        "run must terminate promptly on connection death, took {elapsed:?}"
    );
    assert!(
        stats.recorder.sent < count / 2,
        "actor drained {} of {count} queries — it busy-spun on the dead connection \
         instead of stopping",
        stats.recorder.sent
    );
}
