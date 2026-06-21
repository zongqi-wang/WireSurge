//! PROXY protocol v2 header encoding.
//!
//! The header is written as the very first bytes on a TCP connection, before any
//! TLS ClientHello or DNS frame, so a downstream listener (NLB / Global
//! Resolver) attributes the connection to the carried `src`/`dst` rather than to
//! the real socket peer. WireSurge uses it to present a mocked customer source
//! and the resolver's NLB VIP destination while the socket itself opens to the
//! pod under test. Only the v2 binary PROXY command for TCP is emitted (the only
//! shape the load path needs); LOCAL, UDP, and UNIX address families are not.

use std::net::SocketAddr;

use wiresurge_core::{Result, WireSurgeError};

/// 12-byte v2 signature. Contains a NUL, so it is not a C string.
const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
/// Byte 13: version 2 (upper nibble) + PROXY command (lower nibble).
const VER_CMD: u8 = 0x21;
/// Byte 14: AF_INET + STREAM.
const FAM_TCP4: u8 = 0x11;
/// Byte 14: AF_INET6 + STREAM.
const FAM_TCP6: u8 = 0x21;

/// A source/destination address pair to advertise via PROXY protocol v2. Both
/// endpoints must be the same IP family; mixing v4 and v6 is rejected because
/// the wire format carries a single family byte for the pair.
#[derive(Debug, Clone, Copy)]
pub struct ProxyHeader {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl ProxyHeader {
    pub fn new(src: SocketAddr, dst: SocketAddr) -> Self {
        Self { src, dst }
    }

    /// Serialize the full v2 header (16-byte fixed prefix + address block).
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(52);
        out.extend_from_slice(&SIGNATURE);
        out.push(VER_CMD);

        match (self.src, self.dst) {
            (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
                out.push(FAM_TCP4);
                out.extend_from_slice(&12u16.to_be_bytes());
                out.extend_from_slice(&src.ip().octets());
                out.extend_from_slice(&dst.ip().octets());
                out.extend_from_slice(&src.port().to_be_bytes());
                out.extend_from_slice(&dst.port().to_be_bytes());
            }
            (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
                out.push(FAM_TCP6);
                out.extend_from_slice(&36u16.to_be_bytes());
                out.extend_from_slice(&src.ip().octets());
                out.extend_from_slice(&dst.ip().octets());
                out.extend_from_slice(&src.port().to_be_bytes());
                out.extend_from_slice(&dst.port().to_be_bytes());
            }
            _ => {
                return Err(WireSurgeError::new(
                    "proxy_family_mismatch",
                    "PROXY protocol source and destination must be the same IP family",
                )
                .at("proxy"));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_tcp4_golden_bytes() {
        let header = ProxyHeader::new(
            "192.0.2.1:50000".parse().unwrap(),
            "203.0.113.7:443".parse().unwrap(),
        );
        let bytes = header.encode().unwrap();
        assert_eq!(bytes.len(), 28);
        assert_eq!(&bytes[..12], &SIGNATURE);
        assert_eq!(bytes[12], 0x21);
        assert_eq!(bytes[13], 0x11);
        assert_eq!(&bytes[14..16], &12u16.to_be_bytes());
        assert_eq!(&bytes[16..20], &[192, 0, 2, 1]); // src addr
        assert_eq!(&bytes[20..24], &[203, 0, 113, 7]); // dst addr
        assert_eq!(&bytes[24..26], &50000u16.to_be_bytes()); // src port
        assert_eq!(&bytes[26..28], &443u16.to_be_bytes()); // dst port
    }

    #[test]
    fn encodes_tcp6_golden_bytes() {
        let header = ProxyHeader::new(
            "[2001:db8::1]:50000".parse().unwrap(),
            "[2001:db8::2]:443".parse().unwrap(),
        );
        let bytes = header.encode().unwrap();
        assert_eq!(bytes.len(), 52);
        assert_eq!(&bytes[..12], &SIGNATURE);
        assert_eq!(bytes[12], 0x21);
        assert_eq!(bytes[13], 0x21);
        assert_eq!(&bytes[14..16], &36u16.to_be_bytes());
        let src: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert_eq!(&bytes[16..32], &src.octets());
        assert_eq!(&bytes[32..48], &dst.octets());
        assert_eq!(&bytes[48..50], &50000u16.to_be_bytes());
        assert_eq!(&bytes[50..52], &443u16.to_be_bytes());
    }

    #[test]
    fn rejects_mixed_family() {
        let header = ProxyHeader::new(
            "192.0.2.1:1".parse().unwrap(),
            "[2001:db8::2]:443".parse().unwrap(),
        );
        assert_eq!(header.encode().unwrap_err().code, "proxy_family_mismatch");
    }
}
