use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::client::TlsStream;
use wiresurge_core::{Result, WireSurgeError};

mod ppv2;
mod tls;
pub use ppv2::ProxyHeader;
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

/// HTTP method for a request-carrying connection (DoH uses GET or POST per
/// RFC 8484). Kept as a small protocol-agnostic enum so the transport layer
/// stays free of hyper types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

impl HttpMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
        }
    }
}

/// Everything a request-carrying transport needs to address an HTTP endpoint,
/// independent of the payload. The adapter (e.g. DoH) fills in scheme, authority
/// (`https://abc.example/dns-query`), method, and an optional static query
/// string (the auth token rides here). Generic by design so the same HTTP/2
/// transport can drive a non-DNS API load test.
#[derive(Clone)]
pub struct HttpTemplate {
    pub method: HttpMethod,
    /// Absolute origin form: `https://authority/path` (no query).
    pub base_uri: String,
    /// Pre-encoded query string appended to every request (without a leading
    /// `?`), e.g. `token=...`; empty when unused.
    pub query: String,
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
    /// HTTP request template for request-carrying transports (DoH). `None` for
    /// Do53/DoT.
    pub http: Option<HttpTemplate>,
    /// PROXY protocol v2 header to prepend to a TCP connection (before TLS/DNS).
    /// `None` disables it; only valid on TCP-based transports.
    pub proxy: Option<ProxyHeader>,
}

impl ConnectTarget {
    pub fn new(tcp_addr: SocketAddr) -> Self {
        Self {
            tcp_addr,
            sni: None,
            proto: None,
            tls: None,
            alpn_relaxed: false,
            http: None,
            proxy: None,
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

    pub fn with_http(mut self, template: HttpTemplate) -> Self {
        self.http = Some(template);
        self
    }

    pub fn with_proxy(mut self, proxy: ProxyHeader) -> Self {
        self.proxy = Some(proxy);
        self
    }
}

pub async fn connect_tcp(target: &ConnectTarget) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(target.tcp_addr).await.map_err(|error| {
        WireSurgeError::new("connect_failed", error.to_string())
            .at("server")
            .retryable(true)
    })?;
    stream.set_nodelay(true).map_err(|error| {
        WireSurgeError::new("set_nodelay_failed", error.to_string()).retryable(true)
    })?;
    // The PROXY v2 header is the very first thing on the wire, ahead of the TLS
    // ClientHello or the DNS length-prefixed frame, so a downstream listener
    // reads it before the carried protocol begins. Flush it before handing the
    // stream to the TLS connector, which would otherwise interleave its own
    // first write.
    if let Some(proxy) = &target.proxy {
        let header = proxy.encode()?;
        stream.write_all(&header).await.map_err(|error| {
            WireSurgeError::new("proxy_write_failed", error.to_string())
                .at("proxy")
                .retryable(true)
        })?;
        stream.flush().await.map_err(|error| {
            WireSurgeError::new("proxy_write_failed", error.to_string())
                .at("proxy")
                .retryable(true)
        })?;
    }
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

/// Establish a TCP connection (writing the PROXY v2 preamble first if the target
/// carries one) and wrap it in TLS.
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
