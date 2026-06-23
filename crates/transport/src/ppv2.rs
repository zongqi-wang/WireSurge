//! PROXY protocol v2 header encoding.

use std::net::SocketAddr;

use wiresurge_core::{Result, WireSurgeError};

/// 12-byte v2 signature. Contains a NUL, so it is not a C string.
const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
/// Byte 13: version 2 (upper nibble) + PROXY command (lower nibble).
const VER_CMD: u8 = 0x21;
const AF_INET: u8 = 0x10;
const AF_INET6: u8 = 0x20;

/// Transport carried under the PROXY header, selecting byte-14's low nibble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyTransport {
    Stream,
    Dgram,
}

impl ProxyTransport {
    fn proto_nibble(self) -> u8 {
        match self {
            ProxyTransport::Stream => 0x01,
            ProxyTransport::Dgram => 0x02,
        }
    }
}

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

    /// Serialize the full v2 header (16-byte fixed prefix + address block) for
    /// the given carried transport.
    pub fn encode(&self, transport: ProxyTransport) -> Result<Vec<u8>> {
        let proto = transport.proto_nibble();
        let mut out = Vec::with_capacity(52);
        out.extend_from_slice(&SIGNATURE);
        out.push(VER_CMD);

        match (self.src, self.dst) {
            (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
                out.push(AF_INET | proto);
                out.extend_from_slice(&12u16.to_be_bytes());
                out.extend_from_slice(&src.ip().octets());
                out.extend_from_slice(&dst.ip().octets());
            }
            (SocketAddr::V6(src), SocketAddr::V6(dst)) => {
                out.push(AF_INET6 | proto);
                out.extend_from_slice(&36u16.to_be_bytes());
                out.extend_from_slice(&src.ip().octets());
                out.extend_from_slice(&dst.ip().octets());
            }
            _ => {
                return Err(WireSurgeError::new(
                    "proxy_family_mismatch",
                    "PROXY protocol source and destination must be the same IP family",
                )
                .at("proxy"));
            }
        }
        out.extend_from_slice(&self.src.port().to_be_bytes());
        out.extend_from_slice(&self.dst.port().to_be_bytes());
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
        let bytes = header.encode(ProxyTransport::Stream).unwrap();
        assert_eq!(bytes.len(), 28);
        assert_eq!(&bytes[..12], &SIGNATURE);
        assert_eq!(bytes[12], 0x21);
        assert_eq!(bytes[13], 0x11);
        assert_eq!(&bytes[14..16], &12u16.to_be_bytes());
        assert_eq!(&bytes[16..20], &[192, 0, 2, 1]);
        assert_eq!(&bytes[20..24], &[203, 0, 113, 7]);
        assert_eq!(&bytes[24..26], &50000u16.to_be_bytes());
        assert_eq!(&bytes[26..28], &443u16.to_be_bytes());
    }

    #[test]
    fn encodes_udp4_golden_bytes() {
        let header = ProxyHeader::new(
            "52.5.87.206:40000".parse().unwrap(),
            "10.216.17.23:5353".parse().unwrap(),
        );
        let bytes = header.encode(ProxyTransport::Dgram).unwrap();
        assert_eq!(bytes.len(), 28);
        assert_eq!(&bytes[..12], &SIGNATURE);
        assert_eq!(bytes[12], 0x21);
        assert_eq!(bytes[13], 0x12);
        assert_eq!(&bytes[14..16], &12u16.to_be_bytes());
        assert_eq!(&bytes[16..20], &[52, 5, 87, 206]);
        assert_eq!(&bytes[20..24], &[10, 216, 17, 23]);
        assert_eq!(&bytes[24..26], &40000u16.to_be_bytes());
        assert_eq!(&bytes[26..28], &5353u16.to_be_bytes());
    }

    #[test]
    fn encodes_tcp6_golden_bytes() {
        let header = ProxyHeader::new(
            "[2001:db8::1]:50000".parse().unwrap(),
            "[2001:db8::2]:443".parse().unwrap(),
        );
        let bytes = header.encode(ProxyTransport::Stream).unwrap();
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
        assert_eq!(
            header.encode(ProxyTransport::Stream).unwrap_err().code,
            "proxy_family_mismatch"
        );
    }
}
