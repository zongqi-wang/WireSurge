//! PROXY protocol v2 lands on the wire ahead of the framed DNS protocol, via the
//! real `TcpTransport` connect path (`connect_tcp`, shared with DoT). A loopback
//! TCP server reads and validates the 28-byte v2 TCPv4 header before serving
//! length-prefixed DNS, so a missing, malformed, or mis-ordered preamble fails
//! the exchange.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wiresurge_dns::build_query;
use wiresurge_dns::transport::do53::TcpTransport;
use wiresurge_dns::transport::{Connection, DnsRequest, Transport};
use wiresurge_transport::{ConnectTarget, ProxyHeader};

const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
const SRC: &str = "192.0.2.10:50000";
const DST: &str = "203.0.113.5:443";

/// Accept one connection, require a well-formed v2 TCPv4 PROXY header carrying
/// the expected src/dst, then echo length-prefixed DNS responses. Sends the
/// observed header back to the caller over `report` so the test can assert the
/// exact bytes that arrived.
async fn spawn_proxy_checked_echo(report: tokio::sync::oneshot::Sender<Vec<u8>>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();

        // Fixed 16-byte prefix, then the v4 address block is exactly 12 bytes.
        let mut fixed = [0u8; 16];
        tcp.read_exact(&mut fixed).await.unwrap();
        assert_eq!(&fixed[..12], &SIGNATURE, "PROXY v2 signature");
        assert_eq!(fixed[12], 0x21, "version+command");
        assert_eq!(fixed[13], 0x11, "AF_INET+STREAM");
        let block_len = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;
        assert_eq!(block_len, 12, "IPv4 address block length");
        let mut block = vec![0u8; block_len];
        tcp.read_exact(&mut block).await.unwrap();

        let mut full = fixed.to_vec();
        full.extend_from_slice(&block);
        let _ = report.send(full);

        // Now serve length-prefixed DNS: echo each query with the response bit.
        loop {
            let mut len_buf = [0u8; 2];
            if tcp.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut msg = vec![0u8; len];
            if tcp.read_exact(&mut msg).await.is_err() {
                break;
            }
            msg[2] = 0x81;
            msg[3] = 0x80;
            let mut frame = Vec::with_capacity(msg.len() + 2);
            frame.extend_from_slice(&(msg.len() as u16).to_be_bytes());
            frame.extend_from_slice(&msg);
            if tcp.write_all(&frame).await.is_err() {
                break;
            }
            let _ = tcp.flush().await;
        }
    });
    addr
}

fn request() -> DnsRequest {
    DnsRequest {
        wire: build_query(0, "example.com", 1, None).unwrap(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_v2_header_precedes_framed_dns() {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let addr = spawn_proxy_checked_echo(tx).await;

    let proxy = ProxyHeader::new(SRC.parse().unwrap(), DST.parse().unwrap());
    let target = ConnectTarget::new(addr).with_proxy(proxy);
    let conn = TcpTransport::connect(target).await.unwrap();

    let response = conn
        .exchange(request(), Duration::from_secs(5))
        .await
        .expect("DNS exchange after the PROXY preamble must succeed");
    assert_eq!(response.rcode, 0);

    // The header the server actually read must match the configured src/dst.
    let observed = rx.await.unwrap();
    assert_eq!(observed.len(), 28);
    assert_eq!(&observed[16..20], &[192, 0, 2, 10]); // src addr
    assert_eq!(&observed[20..24], &[203, 0, 113, 5]); // dst addr
    assert_eq!(&observed[24..26], &50000u16.to_be_bytes()); // src port
    assert_eq!(&observed[26..28], &443u16.to_be_bytes()); // dst port
}
