#![allow(dead_code)]

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use data_encoding::BASE64URL_NOPAD;
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
use wiresurge_dns::transport::DnsRequest;
use wiresurge_transport::{
    AppProto, ConnectTarget, HttpMethod, HttpTemplate, TlsParams, build_client_config,
};

pub const CERT_DER: &[u8] = include_bytes!("cert.der");
pub const KEY_DER: &[u8] = include_bytes!("key.der");
pub const DNS_MESSAGE: &str = "application/dns-message";

pub fn server_config() -> Arc<ServerConfig> {
    let cert = CertificateDer::from(CERT_DER.to_vec());
    let key = PrivateKeyDer::try_from(KEY_DER.to_vec()).unwrap();
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(config)
}

pub async fn extract_wire(request: Request<Incoming>) -> Option<Vec<u8>> {
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

pub fn dns_response(mut wire: Vec<u8>) -> Response<Full<Bytes>> {
    wire[2] = 0x81;
    wire[3] = 0x80;
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, DNS_MESSAGE)
        .body(Full::new(Bytes::from(wire)))
        .unwrap()
}

pub fn request_with_id(id: u16) -> DnsRequest {
    DnsRequest {
        wire: build_query(id, "example.com", 1, &[]).unwrap(),
    }
}

pub fn doh_target(addr: SocketAddr, method: HttpMethod, query: &str) -> ConnectTarget {
    doh_target_with(
        addr,
        method,
        query,
        "localhost",
        "https://localhost/dns-query",
    )
}

pub fn doh_target_with(
    addr: SocketAddr,
    method: HttpMethod,
    query: &str,
    sni: &str,
    base_uri: &str,
) -> ConnectTarget {
    let config = build_client_config(&TlsParams {
        proto: AppProto::Doh,
        insecure: true,
    })
    .unwrap();
    ConnectTarget::new(addr)
        .with_tls(config, AppProto::Doh, Some(sni.to_string()), false)
        .with_http(HttpTemplate {
            method,
            base_uri: base_uri.to_string(),
            query: query.to_string(),
        })
}

pub async fn spawn_doh_server_on<F, Fut>(bind: &str, handler: F) -> Option<SocketAddr>
where
    F: Fn(String, Vec<u8>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response<Full<Bytes>>> + Send,
{
    let listener = TcpListener::bind(bind).await.ok()?;
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config());
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let acceptor = acceptor.clone();
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let tls = match acceptor.accept(tcp).await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                let service = service_fn(move |request: Request<Incoming>| {
                    let handler = Arc::clone(&handler);
                    async move {
                        let query = request.uri().query().unwrap_or("").to_string();
                        let Some(wire) = extract_wire(request).await else {
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::BAD_REQUEST)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap(),
                            );
                        };
                        Ok::<_, Infallible>(handler(query, wire).await)
                    }
                });
                let _ = server_http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    Some(addr)
}
