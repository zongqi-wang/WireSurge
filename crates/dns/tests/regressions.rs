//! P0-A regressions (P0A-04): DNS accounting honesty — each test pins the
//! ADR 0004 contract.

mod fixtures;

use std::time::Duration;

use wiresurge_dns::parse_response_header;
use wiresurge_dns::transport::doh::DohTransport;
use wiresurge_dns::transport::{Connection, Transport, TransportError};
use wiresurge_transport::{ConnectTarget, HttpMethod};

/// DNS response header echoing the request id, with the QR/RA flags set.
fn response_with_question(request_wire: &[u8], qname: &[u8], arcount: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&request_wire[..2]);
    out.extend_from_slice(&[0x81, 0x80]);
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, arcount]);
    out.extend_from_slice(qname);
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    out
}

/// Same request id, different question (evil.com), rcode NOERROR.
fn wrong_question_response(request_wire: &[u8]) -> Vec<u8> {
    response_with_question(
        request_wire,
        &[4, b'e', b'v', b'i', b'l', 3, b'c', b'o', b'm', 0],
        0,
    )
}

/// Extended-RCODE response: header rcode bits are 0 (NOERROR), but the OPT
/// record TTL carries the extended RCODE high bits — extended RCODE 16
/// (BADVERS) per RFC 6891 §6.1.3.
fn badvers_response(request_wire: &[u8]) -> Vec<u8> {
    let mut out = response_with_question(
        request_wire,
        &[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ],
        1,
    );
    out.extend_from_slice(&[
        0x00, 0x00, 0x29, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    out
}

#[test]
fn extended_rcode_16_surfaces_as_badvers_not_noerror() {
    let wire = badvers_response(&fixtures::request_with_id(0x1234).wire);
    let header = parse_response_header(&wire, None).expect("wire must parse");
    assert_eq!(
        header.rcode, 16,
        "BADVERS (extended RCODE 16) must not be counted as NOERROR"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_response_with_mismatched_question_is_rejected() {
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let responder = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (len, peer) = server.recv_from(&mut buf).await.unwrap();
        let reply = wrong_question_response(&buf[..len]);
        server.send_to(&reply, peer).await.unwrap();
    });

    let conn = wiresurge_dns::transport::do53::UdpTransport::connect(ConnectTarget::new(addr))
        .await
        .expect("udp transport must connect");
    let result = conn
        .exchange(fixtures::request_with_id(0x1234), Duration::from_secs(2))
        .await;
    responder.await.unwrap();

    assert!(
        matches!(result, Err(TransportError::Protocol(_))),
        "a UDP response whose question differs from the query must be rejected, got {result:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn doh_response_with_mismatched_question_is_rejected() {
    let addr = fixtures::spawn_doh_server_on("127.0.0.1:0", |_, wire| async move {
        fixtures::dns_response(wrong_question_response(&wire))
    })
    .await
    .expect("doh fixture must bind");

    let conn = DohTransport::connect(fixtures::doh_target(addr, HttpMethod::Post, ""))
        .await
        .expect("doh transport must connect");
    let result = conn
        .exchange(fixtures::request_with_id(0x1234), Duration::from_secs(5))
        .await;

    assert!(
        matches!(result, Err(TransportError::Protocol(_))),
        "a DoH response whose question differs from the query must be rejected, got {result:?}"
    );
}
