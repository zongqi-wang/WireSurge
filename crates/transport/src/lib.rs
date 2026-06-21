use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::client::TlsStream;
use wiresurge_core::{Result, WireSurgeError};

mod tls;
pub use tls::{TlsParams, build_client_config};

/// Application protocol carried over a connection, used to negotiate ALPN and to
/// resolve the relaxed-ALPN fallback (assume this protocol when the peer offers
/// none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppProto {
    Dot,
    Doh,
}

impl AppProto {
    fn alpn(self) -> &'static [u8] {
        match self {
            AppProto::Dot => b"dot",
            AppProto::Doh => b"h2",
        }
    }
}

/// Where a connection is established and how it is framed before the carried
/// protocol begins. The `tcp_addr` is always the real socket peer (e.g. the
/// pod), independent of any PROXY-protocol source/destination addresses added
/// in a later stage. When `tls` is set, the stream is wrapped with TLS using
/// `sni` for the server name and `proto` for ALPN.
#[derive(Clone)]
pub struct ConnectTarget {
    pub tcp_addr: SocketAddr,
    pub sni: Option<String>,
    pub proto: Option<AppProto>,
    pub tls: Option<Arc<rustls::ClientConfig>>,
    pub alpn_relaxed: bool,
}

impl ConnectTarget {
    pub fn new(tcp_addr: SocketAddr) -> Self {
        Self {
            tcp_addr,
            sni: None,
            proto: None,
            tls: None,
            alpn_relaxed: false,
        }
    }

    pub fn with_tls(
        mut self,
        config: Arc<rustls::ClientConfig>,
        proto: AppProto,
        sni: Option<String>,
        alpn_relaxed: bool,
    ) -> Self {
        self.tls = Some(config);
        self.proto = Some(proto);
        self.sni = sni;
        self.alpn_relaxed = alpn_relaxed;
        self
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

/// Establish a TCP connection and wrap it in TLS. The PROXY-protocol preamble
/// (Stage 5) belongs between the TCP connect and the TLS handshake; it has not
/// landed yet, so this is the seam where it will go.
pub async fn connect_tls(target: &ConnectTarget) -> Result<TlsStream<TcpStream>> {
    let config = target.tls.clone().ok_or_else(|| {
        WireSurgeError::new(
            "tls_not_configured",
            "connect_tls called without a TLS config",
        )
    })?;
    let proto = target.proto.ok_or_else(|| {
        WireSurgeError::new(
            "tls_not_configured",
            "connect_tls called without a protocol",
        )
    })?;
    let tcp = connect_tcp(target).await?;
    let server_name = tls::server_name(target)?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let stream = connector.connect(server_name, tcp).await.map_err(|error| {
        WireSurgeError::new("tls_handshake_failed", error.to_string())
            .at("server")
            .retryable(true)
    })?;
    tls::check_alpn(&stream, proto, target.alpn_relaxed)?;
    Ok(stream)
}
