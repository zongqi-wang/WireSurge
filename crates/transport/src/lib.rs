use std::net::SocketAddr;

use tokio::net::{TcpStream, UdpSocket};
use wiresurge_core::{Result, WireSurgeError};

/// Where a connection is established and how it is framed before the carried
/// protocol begins. TLS and PROXY-protocol-v2 preamble land here in later
/// stages; the `tcp_addr` is always the real socket peer (e.g. the pod), which
/// is independent of any PROXY-protocol source/destination addresses.
#[derive(Debug, Clone)]
pub struct ConnectTarget {
    pub tcp_addr: SocketAddr,
}

impl ConnectTarget {
    pub fn new(tcp_addr: SocketAddr) -> Self {
        Self { tcp_addr }
    }
}

pub async fn connect_tcp(target: &ConnectTarget) -> Result<TcpStream> {
    let stream = TcpStream::connect(target.tcp_addr).await.map_err(|error| {
        WireSurgeError::new("connect_failed", error.to_string())
            .at("server")
            .retryable(true)
    })?;
    stream.set_nodelay(true).map_err(|error| {
        WireSurgeError::new("set_nodelay_failed", error.to_string()).retryable(true)
    })?;
    Ok(stream)
}

pub async fn connect_udp(target: &ConnectTarget) -> Result<UdpSocket> {
    let bind = if target.tcp_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await.map_err(|error| {
        WireSurgeError::new("udp_bind_failed", error.to_string()).retryable(true)
    })?;
    socket.connect(target.tcp_addr).await.map_err(|error| {
        WireSurgeError::new("udp_connect_failed", error.to_string()).retryable(true)
    })?;
    Ok(socket)
}
