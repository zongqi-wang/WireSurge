use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub mod h2;

use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Bytes;
use hyper::header::{HeaderName, HeaderValue, USER_AGENT};
use hyper::{Method, Request, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Serialize;
use url::Url;
use wiresurge_core::scenario::CallResponse;
use wiresurge_core::{RequestSpec, Result, WireSurgeError, redact_value, serialize_json};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;

type HyperClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;
static SHARED_HTTP_CLIENT: OnceLock<std::result::Result<HyperClient, String>> = OnceLock::new();

#[derive(Clone)]
pub struct HttpClient {
    client: HyperClient,
}

impl HttpClient {
    pub fn shared() -> Result<Self> {
        match SHARED_HTTP_CLIENT.get_or_init(|| build_hyper_client().map_err(|error| error.message))
        {
            Ok(client) => Ok(Self {
                client: client.clone(),
            }),
            Err(error) => Err(WireSurgeError::new("tls_root_load_failed", error.clone())
                .with_hint("Check that the operating system trust store is available.")),
        }
    }

    pub async fn send(&self, request: &RequestSpec) -> Result<HttpResponse> {
        let url = parse_url(&request.url)?;
        let method = Method::from_bytes(request.method.as_bytes()).map_err(|error| {
            WireSurgeError::new("invalid_http_method", error.to_string()).at("method")
        })?;
        let uri = url
            .as_str()
            .parse::<Uri>()
            .map_err(|error| WireSurgeError::new("invalid_url", error.to_string()).at("url"))?;
        let body = Full::new(Bytes::from(request.body.clone().unwrap_or_default()));
        let mut outbound = Request::builder()
            .method(method)
            .uri(uri)
            .body(body)
            .map_err(|error| WireSurgeError::new("http_request_build_failed", error.to_string()))?;
        outbound.headers_mut().insert(
            USER_AGENT,
            HeaderValue::from_static(concat!("WireSurge/", env!("CARGO_PKG_VERSION"))),
        );
        for (key, value) in &request.headers {
            if key.eq_ignore_ascii_case("host")
                || key.eq_ignore_ascii_case("connection")
                || key.eq_ignore_ascii_case("content-length")
            {
                continue;
            }
            let name = HeaderName::from_bytes(key.as_bytes()).map_err(|error| {
                WireSurgeError::new("invalid_http_header", error.to_string()).at(key.clone())
            })?;
            let value = HeaderValue::from_str(value).map_err(|error| {
                WireSurgeError::new("invalid_http_header", error.to_string()).at(key.clone())
            })?;
            outbound.headers_mut().insert(name, value);
        }

        let started = Instant::now();
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        let response = tokio::time::timeout_at(deadline, self.client.request(outbound))
            .await
            .map_err(|_| {
                WireSurgeError::new("http_timeout", "HTTP request exceeded 30 seconds")
                    .at("url")
                    .retryable(true)
            })?
            .map_err(|error| {
                WireSurgeError::new("http_request_failed", error.to_string())
                    .at("url")
                    .retryable(true)
            })?;
        let status = response.status();
        let headers = response
            .headers()
            .iter()
            .map(|(key, value)| {
                (
                    key.as_str().to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let body = tokio::time::timeout_at(
            deadline,
            Limited::new(response.into_body(), MAX_RESPONSE_BODY_BYTES).collect(),
        )
        .await
        .map_err(|_| {
            WireSurgeError::new("http_timeout", "HTTP request exceeded 30 seconds")
                .at("url")
                .retryable(true)
        })?
        .map_err(|error| {
            if error.downcast_ref::<LengthLimitError>().is_some() {
                WireSurgeError::new(
                    "http_response_too_large",
                    "HTTP response body exceeds the 16 MiB limit",
                )
            } else {
                WireSurgeError::new("http_response_body_failed", error.to_string()).retryable(true)
            }
        })?
        .to_bytes();
        let duration_ms = started.elapsed().as_secs_f64() * 1000.0;
        let mut warnings = Vec::new();
        if status.is_redirection() {
            warnings.push(
                "redirect response captured; automatic redirect following is disabled".to_string(),
            );
        }
        Ok(HttpResponse {
            status_code: status.as_u16(),
            reason: status.canonical_reason().unwrap_or("").to_string(),
            headers,
            body: String::from_utf8_lossy(&body).into_owned(),
            duration_ms,
            warnings,
        })
    }
}

fn build_hyper_client() -> Result<HyperClient> {
    let connector = HttpsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|error| {
            WireSurgeError::new("tls_root_load_failed", error.to_string())
                .with_hint("Check that the operating system trust store is available.")
        })?
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

pub async fn send_http_request(request: &RequestSpec) -> Result<HttpResponse> {
    HttpClient::shared()?.send(request).await
}

#[derive(Debug, Clone, PartialEq)]
pub struct HttpResponse {
    pub status_code: u16,
    pub reason: String,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    pub duration_ms: f64,
    pub warnings: Vec<String>,
}

impl HttpResponse {
    pub fn to_json(&self) -> Result<String> {
        serialize_json(&self.redacted_output(&[]))
    }

    /// Normalize into the protocol-blind [`CallResponse`] that templating,
    /// extraction, and assertions operate on. HTTP has a status but no separate
    /// protocol code, so `code` is `None`.
    pub fn to_call_response(&self) -> CallResponse {
        CallResponse {
            status: Some(self.status_code),
            code: None,
            headers: self.headers.clone(),
            body: self.body.clone(),
            duration_ms: self.duration_ms,
            warnings: self.warnings.clone(),
        }
    }

    pub fn to_json_value(&self) -> Result<serde_json::Value> {
        self.to_json_value_with(&[])
    }

    /// Like [`HttpResponse::to_json_value`], but also masks the given secret
    /// values — e.g. a `--secret` the target echoes back in its body or a header.
    pub fn to_json_value_with(&self, secret_values: &[String]) -> Result<serde_json::Value> {
        serde_json::to_value(self.redacted_output(secret_values))
            .map_err(|error| WireSurgeError::new("json_encode_failed", error.to_string()))
    }

    fn redacted_output(&self, secret_values: &[String]) -> RedactedHttpResponse<'_> {
        let headers = self
            .headers
            .iter()
            .map(|(key, value)| {
                let value = if is_sensitive_header(key) {
                    "[redacted]".to_string()
                } else {
                    redact_value(value, secret_values)
                };
                (key.clone(), value)
            })
            .collect();
        RedactedHttpResponse {
            status_code: self.status_code,
            reason: &self.reason,
            headers,
            body: redact_value(&self.body, secret_values),
            duration_ms: self.duration_ms,
            warnings: &self.warnings,
        }
    }
}

#[derive(Serialize)]
struct RedactedHttpResponse<'a> {
    status_code: u16,
    reason: &'a str,
    headers: BTreeMap<String, String>,
    body: String,
    duration_ms: f64,
    warnings: &'a [String],
}

fn parse_url(input: &str) -> Result<Url> {
    let mut url = Url::parse(input)
        .map_err(|error| WireSurgeError::new("invalid_url", error.to_string()).at("url"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(WireSurgeError::new(
            "invalid_url",
            "only http:// and https:// URLs are supported",
        )
        .at("url"));
    }
    if url.host().is_none() {
        return Err(WireSurgeError::new("invalid_url", "host is required").at("url"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(WireSurgeError::new(
            "invalid_url",
            "credentials in URLs are not supported; use an Authorization header",
        )
        .at("url"));
    }
    url.set_fragment(None);
    Ok(url)
}

fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key"
    )
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    #[test]
    fn rejects_url_credentials() {
        let error = parse_url("https://user:pass@example.com/").unwrap_err();
        assert_eq!(error.code, "invalid_url");
    }

    #[test]
    fn masks_echoed_secret_value_in_response() {
        // A secret value the target echoes back (no redaction marker) must be
        // masked when the response is serialized.
        let response = HttpResponse {
            status_code: 200,
            reason: "OK".to_string(),
            headers: BTreeMap::new(),
            body: r#"{"echo":"aGVsbG8xMjM0NQ"}"#.to_string(),
            duration_ms: 0.0,
            warnings: Vec::new(),
        };
        let value = response
            .to_json_value_with(&["aGVsbG8xMjM0NQ".to_string()])
            .unwrap();
        let body = value.get("body").and_then(|b| b.as_str()).unwrap();
        assert!(!body.contains("aGVsbG8xMjM0NQ"), "{body}");
        assert!(body.contains("[redacted]"), "{body}");
    }

    #[tokio::test]
    #[ignore = "requires permission to bind localhost TCP sockets"]
    async fn sends_local_http_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer).unwrap();
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
                )
                .unwrap();
        });
        let request = RequestSpec::from_json(&format!(
            r#"{{"id":"req","name":"local","url":"http://{}"}}"#,
            addr
        ))
        .unwrap();
        let response = send_http_request(&request).await.unwrap();
        assert_eq!(response.status_code, 200);
        assert_eq!(response.body, "hello");
    }
}
