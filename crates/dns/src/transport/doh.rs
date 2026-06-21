//! DNS-over-HTTPS (RFC 8484) as a thin adapter over the generic HTTP/2 load
//! transport in `wiresurge-http`. This file owns only the DoH-specific framing:
//! how a DNS wire message maps to an HTTP request and how the HTTP response maps
//! back to a `DnsResponse`. The connection, multiplexing, flow control, and
//! GOAWAY handling all live in the reusable `wiresurge_http::h2` layer.
//!
//! Correlation: HTTP/2 binds each response to its own stream, so there is no
//! transaction-id demux as on Do53/DoT. RFC 8484 §4.1 says the DNS ID SHOULD be
//! 0 on DoH; the query is built with id 0 and we report it verbatim.

use std::time::Duration;

use data_encoding::BASE64URL_NOPAD;
use hyper::Method;
use hyper::header::{ACCEPT, CONTENT_TYPE, HeaderValue};
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
    template: HttpTemplate,
}

impl Transport for DohTransport {
    type Conn = DohConn;

    async fn connect(target: ConnectTarget) -> Result<DohConn, TransportError> {
        let template = target.http.clone().ok_or_else(|| {
            TransportError::Protocol("DoH connect target is missing its HTTP template".into())
        })?;
        let stream = connect_tls(&target)
            .await
            .map_err(|error| TransportError::Io(error.to_string()))?;
        let sender = handshake(stream, &H2Config::default())
            .await
            .map_err(map_h2)?;
        Ok(DohConn { sender, template })
    }
}

impl DohConn {
    /// Build the request URI and body for one query. GET carries the message as
    /// a base64url (`?dns=`) parameter and an empty body; POST carries the raw
    /// wire bytes as the body. Any template query (the auth token) is preserved
    /// and joined ahead of `dns=`.
    fn build(&self, wire: &[u8]) -> Result<(String, Vec<u8>), TransportError> {
        let mut uri = String::with_capacity(self.template.base_uri.len() + wire.len() * 2);
        uri.push_str(&self.template.base_uri);

        match self.template.method {
            HttpMethod::Get => {
                let encoded = BASE64URL_NOPAD.encode(wire);
                uri.push('?');
                if !self.template.query.is_empty() {
                    uri.push_str(&self.template.query);
                    uri.push('&');
                }
                uri.push_str("dns=");
                uri.push_str(&encoded);
                Ok((uri, Vec::new()))
            }
            HttpMethod::Post => {
                if !self.template.query.is_empty() {
                    uri.push('?');
                    uri.push_str(&self.template.query);
                }
                Ok((uri, wire.to_vec()))
            }
        }
    }
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
        let (uri, body) = self.build(&request.wire)?;
        let uri = uri
            .parse::<hyper::Uri>()
            .map_err(|error| TransportError::Protocol(format!("invalid DoH URI: {error}")))?;
        let method = match self.template.method {
            HttpMethod::Get => Method::GET,
            HttpMethod::Post => Method::POST,
        };
        let mut headers = vec![(ACCEPT, HeaderValue::from_static(DNS_MESSAGE))];
        if matches!(self.template.method, HttpMethod::Post) {
            headers.push((CONTENT_TYPE, HeaderValue::from_static(DNS_MESSAGE)));
        }

        let h2_request = H2Request {
            method,
            uri,
            headers,
            body: body.into(),
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
