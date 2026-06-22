use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use wiresurge_dns::build_query;
use wiresurge_dns::transport::dot::DotTransport;
use wiresurge_dns::transport::{Connection, DnsRequest, Transport, TransportError};
use wiresurge_transport::{AppProto, ConnectTarget, TlsParams, build_client_config};

const CERT_DER: &[u8] = include_bytes!("fixtures/cert.der");
const KEY_DER: &[u8] = include_bytes!("fixtures/key.der");

/// Behaviour of the DoT echo server for a given test.
#[derive(Clone, Copy)]
enum ServerMode {
    /// Echo every query back with the response bit set.
    Echo,
    /// Echo, but silently swallow every other query so the client must reap the
    /// slot on timeout.
    DropEveryOther,
    /// Negotiate no ALPN at all (exercises the relaxed-ALPN client path).
    EchoNoAlpn,
}

fn server_config(mode: ServerMode) -> Arc<ServerConfig> {
    let cert = CertificateDer::from(CERT_DER.to_vec());
    let key = PrivateKeyDer::try_from(KEY_DER.to_vec()).unwrap();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    if !matches!(mode, ServerMode::EchoNoAlpn) {
        config.alpn_protocols = vec![b"dot".to_vec()];
    }
    Arc::new(config)
}

async fn spawn_dot_echo(mode: ServerMode) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config(mode));
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(tcp).await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                let mut seen = 0u64;
                loop {
                    let mut len_buf = [0u8; 2];
                    if tls.read_exact(&mut len_buf).await.is_err() {
                        break;
                    }
                    let len = u16::from_be_bytes(len_buf) as usize;
                    let mut msg = vec![0u8; len];
                    if tls.read_exact(&mut msg).await.is_err() {
                        break;
                    }
                    seen += 1;
                    if matches!(mode, ServerMode::DropEveryOther) && seen.is_multiple_of(2) {
                        continue;
                    }
                    msg[2] = 0x81;
                    msg[3] = 0x80;
                    let mut frame = Vec::with_capacity(msg.len() + 2);
                    frame.extend_from_slice(&(msg.len() as u16).to_be_bytes());
                    frame.extend_from_slice(&msg);
                    if tls.write_all(&frame).await.is_err() {
                        break;
                    }
                    // Flush so the encrypted records reach the socket; rustls
                    // otherwise buffers a burst's trailing replies internally.
                    if tls.flush().await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

fn target(addr: SocketAddr, relaxed: bool) -> ConnectTarget {
    let config = build_client_config(&TlsParams {
        proto: AppProto::Dot,
        insecure: true,
    })
    .unwrap();
    ConnectTarget::new(addr).with_tls(
        config,
        AppProto::Dot,
        Some("localhost".to_string()),
        relaxed,
    )
}

fn request() -> DnsRequest {
    DnsRequest {
        wire: build_query(0, "example.com", 1, &[]).unwrap().into(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dot_many_in_flight_demuxes_by_txid() {
    let addr = spawn_dot_echo(ServerMode::Echo).await;
    let conn = DotTransport::connect(target(addr, false)).await.unwrap();

    let count = 500usize;
    let mut inflight = FuturesUnordered::new();
    for _ in 0..count {
        inflight.push(conn.exchange(request(), Duration::from_secs(5)));
    }

    let mut correlations = std::collections::HashSet::new();
    while let Some(result) = inflight.next().await {
        let response = result.expect("each query must resolve");
        assert_eq!(response.rcode, 0);
        // Each completion carries the txid the writer assigned. A correct demux
        // delivers every reply to a distinct waiter, so the set of correlations
        // must have exactly `count` unique ids; a collision would lose one.
        assert!(
            correlations.insert(response.correlation),
            "duplicate correlation {} — demux delivered one reply to two waiters",
            response.correlation
        );
    }
    assert_eq!(correlations.len(), count);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dot_timeout_frees_the_slot() {
    let addr = spawn_dot_echo(ServerMode::DropEveryOther).await;
    let conn = DotTransport::connect(target(addr, false)).await.unwrap();

    let mut timeouts = 0usize;
    let mut answered = 0usize;
    let mut inflight = FuturesUnordered::new();
    for _ in 0..100 {
        inflight.push(conn.exchange(request(), Duration::from_millis(300)));
    }
    while let Some(result) = inflight.next().await {
        match result {
            Ok(_) => answered += 1,
            Err(TransportError::Timeout) => timeouts += 1,
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
    // The server drops every second query, so roughly half are answered and
    // half time out. A tight band catches both a demux that loses extra replies
    // and a timeout path that fails to free the slot.
    assert!(
        (30..=70).contains(&answered),
        "expected ~50 answered, got {answered}"
    );
    assert!(
        (30..=70).contains(&timeouts),
        "expected ~50 timeouts, got {timeouts}"
    );
    assert_eq!(answered + timeouts, 100);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dot_relaxed_alpn_proceeds_when_peer_omits_alpn() {
    let addr = spawn_dot_echo(ServerMode::EchoNoAlpn).await;
    let conn = DotTransport::connect(target(addr, true)).await.unwrap();
    let response = conn
        .exchange(request(), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(response.rcode, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dot_strict_alpn_rejects_peer_without_alpn() {
    let addr = spawn_dot_echo(ServerMode::EchoNoAlpn).await;
    let result = DotTransport::connect(target(addr, false)).await;
    assert!(
        result.is_err(),
        "strict ALPN must reject a peer that offers none"
    );
}

/// PROXY v2 header precedes the TLS ClientHello on the DoT path. The server reads
/// the 28-byte v4 PROXY header off the raw TCP stream BEFORE handing it to the
/// TLS acceptor; if the header were written after (or interleaved with) the
/// ClientHello, the signature read would consume handshake bytes and the TLS
/// accept would fail. This is the high-risk ordering path that the plain-TCP
/// proxy test cannot exercise.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dot_proxy_header_precedes_client_hello() {
    use wiresurge_transport::ProxyHeader;

    const SIGNATURE: [u8; 12] = [
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config(ServerMode::Echo));
    tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        // Read the PROXY preamble in the clear, before any TLS bytes.
        let mut fixed = [0u8; 16];
        tcp.read_exact(&mut fixed).await.unwrap();
        assert_eq!(
            &fixed[..12],
            &SIGNATURE,
            "PROXY signature before ClientHello"
        );
        assert_eq!(fixed[13], 0x11, "TCPv4 family");
        let block_len = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;
        let mut block = vec![0u8; block_len];
        tcp.read_exact(&mut block).await.unwrap();
        // Now the remaining stream is the TLS handshake + DoT frames.
        let mut tls = acceptor.accept(tcp).await.unwrap();
        let mut len_buf = [0u8; 2];
        if tls.read_exact(&mut len_buf).await.is_ok() {
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut msg = vec![0u8; len];
            if tls.read_exact(&mut msg).await.is_ok() {
                msg[2] = 0x81;
                msg[3] = 0x80;
                let mut frame = Vec::with_capacity(msg.len() + 2);
                frame.extend_from_slice(&(msg.len() as u16).to_be_bytes());
                frame.extend_from_slice(&msg);
                let _ = tls.write_all(&frame).await;
                let _ = tls.flush().await;
            }
        }
    });

    let proxy = ProxyHeader::new(
        "192.0.2.10:50000".parse().unwrap(),
        "203.0.113.5:443".parse().unwrap(),
    );
    let conn = DotTransport::connect(target(addr, false).with_proxy(proxy))
        .await
        .expect("DoT connect with a PROXY preamble must succeed");
    let response = conn
        .exchange(request(), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(response.rcode, 0);
}
