use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::CONTENT_TYPE;
use hyper::{Response, StatusCode};
use wiresurge_dns::transport::doh::DohTransport;
use wiresurge_dns::transport::{Connection, Transport, TransportError};
use wiresurge_transport::HttpMethod;

use fixtures::{DNS_MESSAGE, dns_response, doh_target, spawn_doh_server_on};

mod fixtures;

const QUERY_PARAM: &str = "key=test-value";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_post_many_in_flight_each_stream_isolated() {
    let addr = spawn_doh_server_on("127.0.0.1:0", |_, wire| async move { dns_response(wire) })
        .await
        .unwrap();
    let conn = DohTransport::connect(doh_target(addr, HttpMethod::Post, ""))
        .await
        .unwrap();

    let count = 200u16;
    let mut inflight = FuturesUnordered::new();
    for id in 0..count {
        inflight.push(conn.exchange(fixtures::request_with_id(id), Duration::from_secs(5)));
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
    let addr = spawn_doh_server_on("127.0.0.1:0", |_, wire| async move { dns_response(wire) })
        .await
        .unwrap();
    let conn = DohTransport::connect(doh_target(addr, HttpMethod::Get, ""))
        .await
        .unwrap();
    let response = conn
        .exchange(fixtures::request_with_id(7), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(response.rcode, 0);
    assert_eq!(response.correlation, 7);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_timeout_frees_the_slot() {
    // Echo, but stall one in every two queries past the client timeout so the
    // client must reap the slot.
    let seen = Arc::new(AtomicU64::new(0));
    let addr = spawn_doh_server_on("127.0.0.1:0", move |_, wire| {
        let seen = Arc::clone(&seen);
        async move {
            if seen.fetch_add(1, Ordering::Relaxed) % 2 == 1 {
                // Outlive the client timeout; the client drops the future
                // (RST_STREAM) and the sleep is cancelled with it.
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
            dns_response(wire)
        }
    })
    .await
    .unwrap();
    let conn = DohTransport::connect(doh_target(addr, HttpMethod::Post, ""))
        .await
        .unwrap();

    let mut answered = 0usize;
    let mut timeouts = 0usize;
    let mut inflight = FuturesUnordered::new();
    for id in 0..100u16 {
        inflight.push(conn.exchange(fixtures::request_with_id(id), Duration::from_millis(300)));
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
    let addr = spawn_doh_server_on("127.0.0.1:0", move |query, wire| async move {
        if query.split('&').any(|pair| pair == QUERY_PARAM) {
            dns_response(wire)
        } else {
            Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Full::new(Bytes::new()))
                .unwrap()
        }
    })
    .await
    .unwrap();

    let with_param = DohTransport::connect(doh_target(addr, HttpMethod::Post, QUERY_PARAM))
        .await
        .unwrap();
    let response = with_param
        .exchange(fixtures::request_with_id(1), Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(response.rcode, 0);

    let without_param = DohTransport::connect(doh_target(addr, HttpMethod::Post, ""))
        .await
        .unwrap();
    let result = without_param
        .exchange(fixtures::request_with_id(2), Duration::from_secs(5))
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
    let addr = spawn_doh_server_on("127.0.0.1:0", |_, mut wire| async move {
        wire[0] = 0;
        wire[1] = 0;
        wire[2] = 0x81;
        wire[3] = 0x80;
        Response::builder()
            .status(StatusCode::ACCEPTED)
            .header(CONTENT_TYPE, DNS_MESSAGE)
            .body(Full::new(Bytes::from(wire)))
            .unwrap()
    })
    .await
    .unwrap();
    let conn = DohTransport::connect(doh_target(addr, HttpMethod::Post, ""))
        .await
        .unwrap();
    let response = conn
        .exchange(fixtures::request_with_id(42), Duration::from_secs(5))
        .await
        .expect("zero-id 202 response must be accepted, not rejected");
    assert_eq!(response.rcode, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn doh_over_ipv6_loopback() {
    // Full IPv6 socket -> TLS (bracketed SNI exercises the unbracketing fix) ->
    // HTTP/2 path. Skips if IPv6 loopback is unavailable in the sandbox.
    let Some(addr) =
        spawn_doh_server_on("[::1]:0", |_, wire| async move { dns_response(wire) }).await
    else {
        eprintln!("skipping: IPv6 loopback bind unavailable");
        return;
    };
    assert!(addr.is_ipv6(), "responder must be bound on IPv6");
    let target = fixtures::doh_target_with(
        addr,
        HttpMethod::Post,
        "",
        "[::1]",
        "https://[::1]/dns-query",
    );
    let conn = DohTransport::connect(target)
        .await
        .expect("DoH connect over IPv6 loopback");
    let response = conn
        .exchange(fixtures::request_with_id(11), Duration::from_secs(5))
        .await
        .expect("DoH exchange over IPv6 loopback");
    assert_eq!(response.rcode, 0);
    assert_eq!(response.correlation, 11);
}
