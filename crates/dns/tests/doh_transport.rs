use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use data_encoding::BASE64URL_NOPAD;
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::server::conn::http2 as server_http2;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use wiresurge_dns::build_query;
use wiresurge_dns::transport::doh::DohTransport;
use wiresurge_dns::transport::{Connection, DnsRequest, Transport, TransportError};
use wiresurge_transport::{
    AppProto, ConnectTarget, HttpMethod, HttpTemplate, TlsParams, build_client_config,
};

const CERT_DER: &[u8] = include_bytes!("fixtures/cert.der");
const KEY_DER: &[u8] = include_bytes!("fixtures/key.der");
const DNS_MESSAGE: &str = "application/dns-message";
const QUERY_PARAM: &str = "key=test-value";

#[derive(Clone, Copy)]
enum ServerMode {
    /// Echo every query back as a DNS response (works for GET and POST).
    Echo,
    /// Echo, but stall one in every two queries past the client timeout so the
    /// client must reap the slot.
    StallEveryOther,
    /// Echo only when the request query carries `QUERY_PARAM`; otherwise 403.
    RequireQueryParam,
    /// Model a spec-compliant resolver that returns DNS id 0 (RFC 8484 §4.1)
    /// regardless of the request id, plus a 2xx-but-not-200 status. Exercises
    /// the client paths that must NOT reject on id-mismatch or non-200 2xx.
    ZeroIdAccepted,
}

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

/// Extract the DNS wire message from a DoH request: base64url `?dns=` for GET,
/// the raw body for POST.
async fn extract_wire(request: Request<Incoming>) -> Option<Vec<u8>> {
    let query = request.uri().query().unwrap_or("").to_string();
    if request.method() == Method::GET {
        let encoded = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("dns="))?;
        BASE64URL_NOPAD.decode(encoded.as_bytes()).ok()
    } else {
        let body = request.into_body().collect().await.ok()?.to_bytes();
        Some(body.to_vec())
    }
}

fn dns_response(mut wire: Vec<u8>) -> Response<Full<Bytes>> {
    // Set QR (response) and RA bits so parse_response_header accepts it.
    wire[2] = 0x81;
    wire[3] = 0x80;
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, DNS_MESSAGE)
        .body(Full::new(Bytes::from(wire)))
        .unwrap()
}

async fn spawn_doh_echo(mode: ServerMode) -> SocketAddr {
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
                let tls = match acceptor.accept(tcp).await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                let seen = Arc::new(AtomicU64::new(0));
                let service = service_fn(move |request: Request<Incoming>| {
                    let seen = Arc::clone(&seen);
                    async move {
                        let query = request.uri().query().unwrap_or("").to_string();
                        let nth = seen.fetch_add(1, Ordering::Relaxed);
                        let Some(mut wire) = extract_wire(request).await else {
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::BAD_REQUEST)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            );
                        };
                        match mode {
                            ServerMode::Echo => Ok(dns_response(wire)),
                            ServerMode::StallEveryOther => {
                                if nth % 2 == 1 {
                                    // Outlive the client timeout; the client drops
                                    // the future (RST_STREAM) and the sleep is
                                    // cancelled with it.
                                    tokio::time::sleep(Duration::from_secs(30)).await;
                                }
                                Ok(dns_response(wire))
                            }
                            ServerMode::RequireQueryParam => {
                                if query.split('&').any(|pair| pair == QUERY_PARAM) {
                                    Ok(dns_response(wire))
                                } else {
                                    Ok(Response::builder()
                                        .status(StatusCode::FORBIDDEN)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap())
                                }
                            }
                            ServerMode::ZeroIdAccepted => {
                                wire[0] = 0;
                                wire[1] = 0;
                                wire[2] = 0x81;
                                wire[3] = 0x80;
                                Ok(Response::builder()
                                    .status(StatusCode::ACCEPTED) // 202, a 2xx non-200
                                    .header(CONTENT_TYPE, DNS_MESSAGE)
                                    .body(Full::new(Bytes::from(wire)))
                                    .unwrap())
                            }
                        }
                    }
                });
                let _ = server_http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    addr
}

fn doh_target(addr: SocketAddr, method: HttpMethod, query: &str) -> ConnectTarget {
    let config = build_client_config(&TlsParams {
        proto: AppProto::Doh,
        insecure: true,
    })
    .unwrap();
    ConnectTarget::new(addr)
        .with_tls(config, AppProto::Doh, Some("localhost".to_string()), false)
        .with_http(HttpTemplate {
            method,
            base_uri: "https://localhost/dns-query".to_string(),
            query: query.to_string(),
        })
}

fn request_with_id(id: u16) -> DnsRequest {
    DnsRequest {
        wire: build_query(id, "example.com", 1, &[]).unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_post_many_in_flight_each_stream_isolated() {
    let addr = spawn_doh_echo(ServerMode::Echo).await;
    let conn = DohTransport::connect(doh_target(addr, HttpMethod::Post, ""))
        .await
        .unwrap();

    let count = 200u16;
    let mut inflight = FuturesUnordered::new();
    for id in 0..count {
        inflight.push(conn.exchange(request_with_id(id), Duration::from_secs(5)));
    }

    // Each query carries a distinct DNS id; the adapter validates the echoed id
    // against the one it sent, so a stream delivering the wrong body would error
    // rather than resolve. Unique correlations == count proves hyper bound every
    // response to the right stream.
    let mut correlations = std::collections::HashSet::new();
    while let Some(result) = inflight.next().await {
        let response = result.expect("each query must resolve");
        assert_eq!(response.rcode, 0);
        assert!(
            correlations.insert(response.correlation),
            "duplicate correlation {} — a stream delivered one reply to two waiters",
            response.correlation
        );
    }
    assert_eq!(correlations.len(), count as usize);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_get_encodes_query_in_url() {
    let addr = spawn_doh_echo(ServerMode::Echo).await;
    let conn = DohTransport::connect(doh_target(addr, HttpMethod::Get, ""))
        .await
        .unwrap();
    let response = conn
        .exchange(request_with_id(7), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(response.rcode, 0);
    assert_eq!(response.correlation, 7);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_timeout_frees_the_slot() {
    let addr = spawn_doh_echo(ServerMode::StallEveryOther).await;
    let conn = DohTransport::connect(doh_target(addr, HttpMethod::Post, ""))
        .await
        .unwrap();

    let mut answered = 0usize;
    let mut timeouts = 0usize;
    let mut inflight = FuturesUnordered::new();
    for id in 0..100u16 {
        inflight.push(conn.exchange(request_with_id(id), Duration::from_millis(300)));
    }
    while let Some(result) = inflight.next().await {
        match result {
            Ok(_) => answered += 1,
            Err(TransportError::Timeout) => timeouts += 1,
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
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
async fn doh_query_param_rides_in_url_query() {
    let addr = spawn_doh_echo(ServerMode::RequireQueryParam).await;

    // With the query param present the responder echoes a DNS answer.
    let with_param = DohTransport::connect(doh_target(addr, HttpMethod::Post, QUERY_PARAM))
        .await
        .unwrap();
    let response = with_param
        .exchange(request_with_id(1), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(response.rcode, 0);

    // Without it the responder returns 403, surfaced as a protocol error.
    let without_param = DohTransport::connect(doh_target(addr, HttpMethod::Post, ""))
        .await
        .unwrap();
    let result = without_param
        .exchange(request_with_id(2), Duration::from_secs(5))
        .await;
    assert!(
        matches!(result, Err(TransportError::Protocol(_))),
        "missing query param must be rejected, got {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_accepts_zero_id_and_2xx_non_200() {
    // A spec-compliant resolver returns DNS id 0 (RFC 8484 §4.1) and may use any
    // 2xx status. The client sends a non-zero id but must NOT reject the answer
    // on id-mismatch (HTTP/2 stream is the correlation) nor on the 202 status.
    let addr = spawn_doh_echo(ServerMode::ZeroIdAccepted).await;
    let conn = DohTransport::connect(doh_target(addr, HttpMethod::Post, ""))
        .await
        .unwrap();
    let response = conn
        .exchange(request_with_id(42), Duration::from_secs(5))
        .await
        .expect("zero-id 202 response must be accepted, not rejected");
    assert_eq!(response.rcode, 0);
}
