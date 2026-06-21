//! DNS-over-HTTPS (RFC 8484) as a thin adapter over the generic HTTP/2 load
//! transport in `wiresurge-http`. This file owns only the DoH-specific framing:
//! how a DNS wire message maps to an HTTP request and how the HTTP response maps
//! back to a `DnsResponse`. The connection, multiplexing, flow control, and
//! GOAWAY handling all live in the reusable `wiresurge_http::h2` layer.
//!
//! Correlation: HTTP/2 binds each response to its own stream, so there is no
//! transaction-id demux as on Do53/DoT. RFC 8484 §4.1 says the DNS ID SHOULD be
//! 0 on DoH; the query is built with id 0 and we report it verbatim.

use std::sync::Arc;
use std::time::Duration;

use data_encoding::BASE64URL_NOPAD;
use hyper::body::Bytes;
use hyper::header::{ACCEPT, CONTENT_TYPE, HeaderName, HeaderValue};
use hyper::http::uri::{Authority, Parts, PathAndQuery, Scheme};
use hyper::{Method, Uri};
use wiresurge_http::h2::{H2Config, H2Error, H2Request, H2Sender, handshake};
use wiresurge_transport::{ConnectTarget, HttpMethod, HttpTemplate, connect_tls};

use super::{Connection, DnsRequest, DnsResponse, Transport, TransportCaps, TransportError};
use crate::parse_response_header;

const DNS_MESSAGE: &str = "application/dns-message";

/// Conservative cap on locally-issued streams when the peer's
/// `MAX_CONCURRENT_STREAMS` has not yet been observed. hyper raises the
/// effective limit to the peer's advertised value once the SETTINGS frame
/// arrives; this only bounds the very first burst.
const DOH_IN_FLIGHT: usize = 256;

pub struct DohTransport;

pub struct DohConn {
    sender: H2Sender,
    prepared: Prepared,
}

/// Connection-constant request parts, parsed once at connect time so the
/// per-query `assemble` only builds the variable `dns=<base64>` path-and-query
/// and bumps a few refcounts. The scheme/authority/path come from the static
/// `base_uri`; the header set depends only on the method.
#[doc(hidden)]
pub struct Prepared {
    method: HttpMethod,
    http_method: Method,
    scheme: Scheme,
    authority: Authority,
    /// Decoded path of `base_uri` (no query), e.g. `/dns-query`.
    path: String,
    /// Static template query (the auth token), without a leading `?`; empty when
    /// unused.
    query: String,
    /// Request headers, fixed for the connection. Cloned (refcount bumps) per
    /// query into hyper's owned `HeaderMap`.
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl Prepared {
    pub fn from_template(template: &HttpTemplate) -> Result<Self, TransportError> {
        let uri = template
            .base_uri
            .parse::<Uri>()
            .map_err(|error| TransportError::Protocol(format!("invalid DoH base URI: {error}")))?;
        let parts = uri.into_parts();
        let scheme = parts
            .scheme
            .ok_or_else(|| TransportError::Protocol("DoH base URI is missing its scheme".into()))?;
        let authority = parts.authority.ok_or_else(|| {
            TransportError::Protocol("DoH base URI is missing its authority".into())
        })?;
        let path = parts
            .path_and_query
            .map(|pq| pq.path().to_string())
            .unwrap_or_else(|| "/".to_string());

        let mut headers = vec![(ACCEPT, HeaderValue::from_static(DNS_MESSAGE))];
        if matches!(template.method, HttpMethod::Post) {
            headers.push((CONTENT_TYPE, HeaderValue::from_static(DNS_MESSAGE)));
        }

        Ok(Self {
            method: template.method,
            http_method: match template.method {
                HttpMethod::Get => Method::GET,
                HttpMethod::Post => Method::POST,
            },
            scheme,
            authority,
            path,
            query: template.query.clone(),
            headers,
        })
    }
}

impl Transport for DohTransport {
    type Conn = DohConn;

    async fn connect(target: ConnectTarget) -> Result<DohConn, TransportError> {
        let template = target.http.as_ref().ok_or_else(|| {
            TransportError::Protocol("DoH connect target is missing its HTTP template".into())
        })?;
        let prepared = Prepared::from_template(template)?;
        let stream = connect_tls(&target)
            .await
            .map_err(|error| TransportError::Io(error.to_string()))?;
        let sender = handshake(stream, &H2Config::default())
            .await
            .map_err(map_h2)?;
        Ok(DohConn { sender, prepared })
    }
}

/// Build the variable per-query path-and-query string and the body. GET carries
/// the message as a base64url (`?dns=`) parameter and an empty body; POST carries
/// the raw wire bytes as the body. Any template query (the auth token) is joined
/// ahead of `dns=`. The POST body shares the prebuilt wire buffer (no copy); GET
/// encodes straight into the path-and-query buffer. Only the path-and-query is
/// rebuilt per query — the scheme/authority are connection-constant.
fn build_path_and_query(prepared: &Prepared, wire: &Arc<[u8]>) -> (String, Bytes) {
    match prepared.method {
        HttpMethod::Get => {
            let mut pq = String::with_capacity(
                prepared.path.len()
                    + prepared.query.len()
                    + 6 // "?", optional "&", "dns="
                    + BASE64URL_NOPAD.encode_len(wire.len()),
            );
            pq.push_str(&prepared.path);
            pq.push('?');
            if !prepared.query.is_empty() {
                pq.push_str(&prepared.query);
                pq.push('&');
            }
            pq.push_str("dns=");
            BASE64URL_NOPAD.encode_append(wire, &mut pq);
            (pq, Bytes::new())
        }
        HttpMethod::Post => {
            let mut pq = String::with_capacity(prepared.path.len() + prepared.query.len() + 1);
            pq.push_str(&prepared.path);
            if !prepared.query.is_empty() {
                pq.push('?');
                pq.push_str(&prepared.query);
            }
            (pq, Bytes::from_owner(Arc::clone(wire)))
        }
    }
}

/// Assemble the per-query URI and body from the connection-constant `Prepared`.
/// This is the per-query hot path the `per_query` bench measures; `exchange`
/// wraps it with the network send. Only the path-and-query varies per query;
/// scheme and authority are cloned (refcount bumps) from `Prepared`, and the
/// headers are borrowed straight off `Prepared` (no per-query Vec).
#[doc(hidden)]
pub fn assemble(prepared: &Prepared, wire: &Arc<[u8]>) -> Result<(Uri, Bytes), TransportError> {
    let (pq, body) = build_path_and_query(prepared, wire);
    let path_and_query = PathAndQuery::try_from(pq)
        .map_err(|error| TransportError::Protocol(format!("invalid DoH URI: {error}")))?;
    let mut parts = Parts::default();
    parts.scheme = Some(prepared.scheme.clone());
    parts.authority = Some(prepared.authority.clone());
    parts.path_and_query = Some(path_and_query);
    let uri = Uri::from_parts(parts)
        .map_err(|error| TransportError::Protocol(format!("invalid DoH URI: {error}")))?;
    Ok((uri, body))
}

impl Connection for DohConn {
    fn caps(&self) -> TransportCaps {
        TransportCaps {
            max_in_flight: DOH_IN_FLIGHT,
        }
    }

    fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    async fn exchange(
        &self,
        request: DnsRequest,
        timeout: Duration,
    ) -> Result<DnsResponse, TransportError> {
        if request.wire.len() < 2 {
            return Err(TransportError::Protocol("query shorter than header".into()));
        }
        // RFC 8484 §4.1: the DNS ID is 0 on DoH and the HTTP/2 stream provides
        // correlation. We report the query's own id field verbatim but do NOT
        // validate the response id (a resolver, forwarder, or HTTP cache may
        // legitimately return any id; an equality check would drop valid
        // answers — see parse_response_header's `None` arm).
        let correlation = u16::from_be_bytes([request.wire[0], request.wire[1]]);
        let (uri, body) = assemble(&self.prepared, &request.wire)?;

        let h2_request = H2Request {
            method: self.prepared.http_method.clone(),
            uri,
            headers: &self.prepared.headers,
            body,
        };

        let response = match tokio::time::timeout(timeout, self.sender.send(h2_request)).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => return Err(map_h2(error)),
            Err(_) => return Err(TransportError::Timeout),
        };
        // RFC 8484 §4.2.1: any 2xx with a valid DNS body is a successful response.
        if !(200..300).contains(&response.status) {
            return Err(TransportError::Protocol(format!(
                "DoH responder returned HTTP {}",
                response.status
            )));
        }
        let header = parse_response_header(&response.body, None)
            .map_err(|error| TransportError::Protocol(error.message))?;
        Ok(DnsResponse {
            correlation,
            rcode: header.rcode,
            truncated: header.truncated,
            bytes_in: response.body.len(),
        })
    }

    async fn drain(&self, _grace: Duration) {
        // Each exchange awaits its own response inline (no shared pending map),
        // so once run_actor stops issuing exchanges there is nothing buffered to
        // wait on; the background driver finishes its streams on its own.
    }
}

fn map_h2(error: H2Error) -> TransportError {
    match error {
        H2Error::Closed => TransportError::ConnectionClosed,
        H2Error::TooLarge => TransportError::Protocol("DoH response body too large".into()),
        H2Error::Request(message) => TransportError::Protocol(message),
        H2Error::Io(message) => TransportError::Io(message),
    }
}
