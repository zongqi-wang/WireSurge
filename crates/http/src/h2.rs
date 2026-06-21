//! Generic HTTP/2 load transport over a pre-established byte stream.
//!
//! This layer knows nothing about DNS: a caller hands it an already-connected
//! (and, for `h2`, already-ALPN-negotiated) stream, gets back a cheaply
//! cloneable [`H2Sender`], and issues request/response exchanges that each ride
//! their own multiplexed stream. DoH is one adapter on top of this; a generic
//! HTTP/JSON API load test is another.
//!
//! Concurrency model: hyper's `SendRequest` is an unbounded handle onto a single
//! background driver task that owns the connection and multiplexes every stream.
//! Cloning the sender is cheap (an mpsc handle), so each in-flight exchange
//! clones it and sends concurrently; the driver applies HTTP/2 flow control and
//! the peer's `MAX_CONCURRENT_STREAMS`. There is no manual id demux — the
//! response future is bound to its stream by hyper.

use std::time::Duration;

use http_body_util::{BodyExt, Limited};
use hyper::body::Bytes;
use hyper::client::conn::http2;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Method, Request, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};

use http_body_util::Full;

/// Tuning for one HTTP/2 connection. Defaults favour a high-fan-out load
/// generator carrying small messages: large, non-adaptive flow-control windows
/// so tiny response bodies never stall on `WINDOW_UPDATE`, and a keep-alive ping
/// so an idle pool connection is reaped rather than silently half-open.
#[derive(Debug, Clone, Copy)]
pub struct H2Config {
    pub initial_stream_window: u32,
    pub initial_conn_window: u32,
    pub max_frame_size: u32,
    pub keep_alive_interval: Option<Duration>,
    pub keep_alive_timeout: Duration,
    /// Cap on a single response body; protects the load generator from a
    /// misbehaving peer streaming an unbounded body.
    pub max_response_bytes: usize,
}

impl Default for H2Config {
    fn default() -> Self {
        Self {
            initial_stream_window: 2 * 1024 * 1024,
            initial_conn_window: 8 * 1024 * 1024,
            max_frame_size: 64 * 1024,
            keep_alive_interval: Some(Duration::from_secs(30)),
            keep_alive_timeout: Duration::from_secs(10),
            max_response_bytes: 256 * 1024,
        }
    }
}

/// One HTTP request to issue. The `uri` must be absolute (scheme + authority +
/// path + query); HTTP/2 derives its `:scheme`/`:authority`/`:path` pseudo
/// headers from it, so a relative URI would be rejected by the peer. `headers`
/// is borrowed: the set is connection-constant for a load run, so the caller
/// holds it once and lends it per request rather than reallocating a `Vec` each
/// time (the values still clone into hyper's owned `HeaderMap`).
pub struct H2Request<'a> {
    pub method: Method,
    pub uri: Uri,
    pub headers: &'a [(HeaderName, HeaderValue)],
    pub body: Bytes,
}

/// A fully-received HTTP response: status plus the complete body. The body is
/// drained to end-of-stream before this returns so hyper emits the flow-control
/// updates that let the connection keep serving (a half-drained body otherwise
/// throttles every later stream on the connection).
pub struct H2Response {
    pub status: u16,
    pub body: Bytes,
}

#[derive(Debug)]
pub enum H2Error {
    /// The connection (driver, GOAWAY, or peer close) is gone.
    Closed,
    /// The request could not be sent or its response failed mid-stream.
    Io(String),
    /// The response body exceeded `max_response_bytes`.
    TooLarge,
    /// The request could not be built from the supplied parts.
    Request(String),
}

/// Cheaply cloneable handle onto one HTTP/2 connection. Clone per in-flight
/// exchange; all clones share the one background driver.
#[derive(Clone)]
pub struct H2Sender {
    inner: http2::SendRequest<Full<Bytes>>,
    max_response_bytes: usize,
}

impl H2Sender {
    /// True once the connection has been closed (GOAWAY received, driver gone).
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    /// Issue one request and fully read its response body.
    pub async fn send(&self, request: H2Request<'_>) -> Result<H2Response, H2Error> {
        let mut sender = self.inner.clone();
        let mut builder = Request::builder().method(request.method).uri(request.uri);
        if let Some(headers) = builder.headers_mut() {
            for (name, value) in request.headers {
                headers.insert(name.clone(), value.clone());
            }
        }
        let outbound = builder
            .body(Full::new(request.body))
            .map_err(|error| H2Error::Request(error.to_string()))?;

        let response = sender
            .send_request(outbound)
            .await
            .map_err(|error| map_hyper(&error))?;
        let status = response.status().as_u16();
        let collected = Limited::new(response.into_body(), self.max_response_bytes)
            .collect()
            .await
            .map_err(|error| {
                // http-body-util boxes the limit error; a downcast is the only
                // way to tell "too large" from a genuine stream failure.
                if error
                    .downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some()
                {
                    H2Error::TooLarge
                } else {
                    H2Error::Io(error.to_string())
                }
            })?;
        Ok(H2Response {
            status,
            body: collected.to_bytes(),
        })
    }
}

/// Negotiate HTTP/2 over an already-connected stream (TLS handshake and ALPN
/// already done by the caller) and spawn the background driver. The returned
/// sender stays usable only while the driver task lives; the driver exits when
/// every sender clone is dropped or the connection closes.
pub async fn handshake<T>(io: T, config: &H2Config) -> Result<H2Sender, H2Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .initial_stream_window_size(config.initial_stream_window)
        .initial_connection_window_size(config.initial_conn_window)
        .max_frame_size(config.max_frame_size)
        .keep_alive_interval(config.keep_alive_interval)
        .keep_alive_timeout(config.keep_alive_timeout);

    let (sender, connection) = builder
        .handshake(TokioIo::new(io))
        .await
        .map_err(|error| map_hyper(&error))?;
    tokio::spawn(async move {
        // Driving the connection to completion (rather than dropping it) lets
        // in-flight streams finish and a GOAWAY drain cleanly.
        let _ = connection.await;
    });
    Ok(H2Sender {
        inner: sender,
        max_response_bytes: config.max_response_bytes,
    })
}

fn map_hyper(error: &hyper::Error) -> H2Error {
    // is_timeout covers a keep-alive PING timeout, which kills the whole
    // connection (the driver exits); classify it with the other connection-fatal
    // kinds so the engine counts it as a connection error, not a per-query one.
    if error.is_closed() || error.is_canceled() || error.is_timeout() {
        H2Error::Closed
    } else {
        H2Error::Io(error.to_string())
    }
}
