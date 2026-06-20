use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use wiresurge_core::{
    RequestSpec, Result, WireSurgeError, json_array, json_object, json_string, redact_sensitive,
};

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
    pub fn to_json(&self) -> String {
        let headers = self
            .headers
            .iter()
            .map(|(key, value)| (key.as_str(), json_string(&redact_sensitive(value))))
            .collect::<Vec<_>>();
        json_object(&[
            ("status_code", self.status_code.to_string()),
            ("reason", json_string(&self.reason)),
            ("headers", json_object(&headers)),
            ("body", json_string(&redact_sensitive(&self.body))),
            ("duration_ms", format!("{:.3}", self.duration_ms)),
            (
                "warnings",
                json_array(
                    &self
                        .warnings
                        .iter()
                        .map(|warning| json_string(warning))
                        .collect::<Vec<_>>(),
                ),
            ),
        ])
    }
}

pub fn send_http_request(request: &RequestSpec) -> Result<HttpResponse> {
    let parsed = ParsedUrl::parse(&request.url)?;
    if parsed.scheme == "https" {
        return Err(WireSurgeError::new("https_not_supported_yet", "HTTPS execution is not implemented in the std-only runner")
            .with_hint("Use http:// targets for the current scaffold; TLS support belongs in the next dependency-backed HTTP phase."));
    }

    let started = Instant::now();
    let address = format!("{}:{}", parsed.host, parsed.port);
    let mut stream = TcpStream::connect(address).map_err(|error| {
        WireSurgeError::new("connect_failed", error.to_string())
            .at("url")
            .with_hint("Check that the target host and port are reachable.")
            .retryable(true)
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;

    let body = request.body.as_deref().unwrap_or("");
    let mut wire = String::new();
    wire.push_str(&format!("{} {} HTTP/1.1\r\n", request.method, parsed.path));
    wire.push_str(&format!("Host: {}\r\n", parsed.host_header()));
    wire.push_str("User-Agent: WireSurge/0.1\r\n");
    wire.push_str("Connection: close\r\n");
    if !body.is_empty() && !request.headers.contains_key("content-length") {
        wire.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    for (key, value) in &request.headers {
        if key.eq_ignore_ascii_case("host") || key.eq_ignore_ascii_case("connection") {
            continue;
        }
        wire.push_str(&format!("{key}: {value}\r\n"));
    }
    wire.push_str("\r\n");
    wire.push_str(body);

    stream.write_all(wire.as_bytes())?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let duration_ms = started.elapsed().as_secs_f64() * 1000.0;
    parse_response(&response, duration_ms)
}

fn parse_response(response: &[u8], duration_ms: f64) -> Result<HttpResponse> {
    let raw = String::from_utf8_lossy(response);
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let mut lines = head.lines();
    let status = lines.next().ok_or_else(|| {
        WireSurgeError::new(
            "invalid_http_response",
            "response did not include a status line",
        )
    })?;
    let mut status_parts = status.splitn(3, ' ');
    let _version = status_parts.next();
    let status_code = status_parts
        .next()
        .ok_or_else(|| {
            WireSurgeError::new("invalid_http_response", "response status line missing code")
        })?
        .parse::<u16>()
        .map_err(|_| {
            WireSurgeError::new(
                "invalid_http_response",
                "response status code was not numeric",
            )
        })?;
    let reason = status_parts.next().unwrap_or("").to_string();
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((key, value)) = line.split_once(':') {
            headers.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    let mut warnings = Vec::new();
    if matches!(status_code, 301 | 302 | 303 | 307 | 308) {
        warnings.push("redirect response captured; automatic redirect following is intentionally disabled in the current runner".to_string());
        if status_code == 301 || status_code == 302 || status_code == 303 {
            warnings.push("some clients drop request bodies or selected headers on this redirect class; WireSurge reports the redirect instead of rewriting it".to_string());
        }
    }
    Ok(HttpResponse {
        status_code,
        reason,
        headers,
        body: body.to_string(),
        duration_ms,
        warnings,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedUrl {
    scheme: String,
    host: String,
    port: u16,
    path: String,
}

impl ParsedUrl {
    fn parse(url: &str) -> Result<Self> {
        let (scheme, rest) = url.split_once("://").ok_or_else(|| {
            WireSurgeError::new("invalid_url", "url must include a scheme").at("url")
        })?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(WireSurgeError::new(
                "invalid_url",
                "only http:// and https:// URLs are supported",
            )
            .at("url"));
        }
        let (authority, path) = rest
            .split_once('/')
            .map(|(host, path)| (host, format!("/{path}")))
            .unwrap_or((rest, "/".to_string()));
        let (host, port) = if let Some((host, port)) = authority.rsplit_once(':') {
            let port = port.parse::<u16>().map_err(|_| {
                WireSurgeError::new("invalid_url", "port must be a number").at("url")
            })?;
            (host.to_string(), port)
        } else {
            (
                authority.to_string(),
                if scheme == "https" { 443 } else { 80 },
            )
        };
        if host.is_empty() {
            return Err(WireSurgeError::new("invalid_url", "host is required").at("url"));
        }
        Ok(Self {
            scheme,
            host,
            port,
            path,
        })
    }

    fn host_header(&self) -> String {
        if (self.scheme == "http" && self.port == 80)
            || (self.scheme == "https" && self.port == 443)
        {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use super::*;

    #[test]
    #[ignore = "requires permission to bind localhost TCP sockets"]
    fn sends_local_http_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhello")
                .unwrap();
        });
        let request = RequestSpec::from_json(&format!(
            r#"{{"id":"req","name":"local","url":"http://{}"}}"#,
            addr
        ))
        .unwrap();
        let response = send_http_request(&request).unwrap();
        assert_eq!(response.status_code, 200);
        assert_eq!(response.body, "hello");
    }
}
