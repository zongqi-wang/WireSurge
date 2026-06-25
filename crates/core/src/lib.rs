use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub mod scenario;

pub type Result<T> = std::result::Result<T, WireSurgeError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WireSurgeError {
    pub code: String,
    pub message: String,
    pub path: Option<String>,
    pub hint: Option<String>,
    pub retryable: bool,
}

impl WireSurgeError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            path: None,
            hint: None,
            retryable: false,
        }
    }

    pub fn at(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"code":"json_encode_failed","message":"failed to encode structured error","path":null,"hint":null,"retryable":false}"#.to_string()
        })
    }
}

impl std::fmt::Display for WireSurgeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)?;
        if let Some(hint) = &self.hint {
            write!(formatter, "\nhint: {hint}")?;
        }
        Ok(())
    }
}

impl std::error::Error for WireSurgeError {}

impl From<std::io::Error> for WireSurgeError {
    fn from(error: std::io::Error) -> Self {
        Self::new("io_error", error.to_string())
            .retryable(error.kind() == std::io::ErrorKind::Interrupted)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestSpec {
    pub id: String,
    pub name: String,
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

impl RequestSpec {
    pub fn from_json(input: &str) -> Result<Self> {
        let mut deserializer = serde_json::Deserializer::from_str(input);
        let parsed: RequestSpecInput = serde_path_to_error::deserialize(&mut deserializer)
            .map_err(|error| deserialization_error("invalid_json", error))?;
        deserializer.end().map_err(|error| {
            WireSurgeError::new("invalid_json", error.to_string()).at(format!(
                "line {}, column {}",
                error.line(),
                error.column()
            ))
        })?;
        parsed.into_request(false)
    }

    pub fn from_yaml(input: &str) -> Result<Self> {
        let deserializer = yaml_serde::Deserializer::from_str(input);
        let parsed: RequestSpecInput = serde_path_to_error::deserialize(deserializer)
            .map_err(|error| deserialization_error("invalid_yaml", error))?;
        parsed.into_request(true)
    }

    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            return Err(WireSurgeError::new("invalid_request", "request id is required").at("id"));
        }
        if self.name.trim().is_empty() {
            return Err(
                WireSurgeError::new("invalid_request", "request name is required").at("name"),
            );
        }
        if self.url.trim().is_empty() {
            return Err(
                WireSurgeError::new("invalid_request", "request url is required").at("url"),
            );
        }
        if !(self.url.starts_with("http://") || self.url.starts_with("https://")) {
            return Err(WireSurgeError::new(
                "invalid_request",
                "request url must start with http:// or https://",
            )
            .at("url"));
        }
        if !self.method.chars().all(|char| char.is_ascii_uppercase()) {
            return Err(
                WireSurgeError::new("invalid_request", "method must be uppercase ASCII")
                    .at("method"),
            );
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<String> {
        serialize_json(&self.redacted_output(&[]))
    }

    pub fn to_json_value(&self) -> Result<serde_json::Value> {
        self.to_json_value_with(&[])
    }

    /// Like [`RequestSpec::to_json_value`], but also masks the given secret
    /// values. A request built from a `--secret`-fed template inlines those
    /// values into its fields, where the marker heuristic cannot spot them.
    pub fn to_json_value_with(&self, secret_values: &[String]) -> Result<serde_json::Value> {
        serde_json::to_value(self.redacted_output(secret_values))
            .map_err(|error| WireSurgeError::new("json_encode_failed", error.to_string()))
    }

    fn redacted_output(&self, secret_values: &[String]) -> RedactedRequestSpec<'_> {
        let headers = self
            .headers
            .iter()
            .map(|(key, value)| {
                let value = if contains_sensitive_marker(key) {
                    "[redacted]".to_string()
                } else {
                    redact_value(value, secret_values)
                };
                (key.clone(), value)
            })
            .collect();
        RedactedRequestSpec {
            id: &self.id,
            name: &self.name,
            method: &self.method,
            url: redact_value(&self.url, secret_values),
            headers,
            body: self
                .body
                .as_deref()
                .map(|body| redact_value(body, secret_values)),
        }
    }

    pub fn to_yaml(&self) -> Result<String> {
        yaml_serde::to_string(self)
            .map_err(|error| WireSurgeError::new("yaml_encode_failed", error.to_string()))
    }
}

#[derive(Deserialize)]
pub(crate) struct RequestSpecInput {
    #[serde(default)]
    pub(crate) id: Option<String>,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) method: Option<String>,
    #[serde(default)]
    pub(crate) url: Option<String>,
    #[serde(default)]
    pub(crate) headers: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) body: Option<String>,
}

impl RequestSpecInput {
    fn into_request(self, require_id: bool) -> Result<RequestSpec> {
        let name = self.name.ok_or_else(|| {
            WireSurgeError::new(
                "invalid_request",
                if require_id {
                    "request YAML missing name"
                } else {
                    "missing required string field 'name'"
                },
            )
            .at("name")
        })?;
        let url = self.url.ok_or_else(|| {
            WireSurgeError::new(
                "invalid_request",
                if require_id {
                    "request YAML missing url"
                } else {
                    "missing required string field 'url'"
                },
            )
            .at("url")
        })?;
        let id = match self.id {
            Some(id) => id,
            None if require_id => {
                return Err(
                    WireSurgeError::new("invalid_request", "request YAML missing id").at("id"),
                );
            }
            None => generate_id("req", &name),
        };
        let request = RequestSpec {
            id,
            name,
            method: self
                .method
                .unwrap_or_else(|| "GET".to_string())
                .to_ascii_uppercase(),
            url,
            headers: self
                .headers
                .into_iter()
                .map(|(key, value)| (key.to_ascii_lowercase(), value))
                .collect(),
            body: self.body,
        };
        request.validate()?;
        Ok(request)
    }
}

#[derive(Serialize)]
struct RedactedRequestSpec<'a> {
    id: &'a str,
    name: &'a str,
    method: &'a str,
    url: String,
    headers: BTreeMap<String, String>,
    body: Option<String>,
}

pub(crate) fn deserialization_error<E>(
    code: &'static str,
    error: serde_path_to_error::Error<E>,
) -> WireSurgeError
where
    E: std::fmt::Display,
{
    let path = error.path().to_string();
    let error = WireSurgeError::new(code, error.inner().to_string());
    if path.is_empty() {
        error
    } else {
        error.at(path)
    }
}

pub fn generate_id(prefix: &str, name: &str) -> String {
    let slug = slugify(name);
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    format!("{prefix}-{slug}-{suffix}")
}

pub fn slugify(input: &str) -> String {
    let mut output = String::new();
    for char in input.chars() {
        if char.is_ascii_alphanumeric() {
            output.push(char.to_ascii_lowercase());
        } else if !output.ends_with('-') {
            output.push('-');
        }
    }
    output.trim_matches('-').to_string()
}

pub fn serialize_json<T>(value: &T) -> Result<String>
where
    T: Serialize + ?Sized,
{
    serde_json::to_string(value)
        .map_err(|error| WireSurgeError::new("json_encode_failed", error.to_string()))
}

pub fn redact_sensitive(input: &str) -> String {
    redact_value(input, &[])
}

/// Redact `input` for display: a marker-bearing string (`token`, `secret`, …) is
/// replaced wholesale, and every occurrence of a known secret value is masked in
/// place. The marker heuristic cannot recognize an arbitrary credential, so
/// callers that hold the secret values (e.g. a templated request built from
/// `--secret`) pass them here to scrub what the marker would miss.
pub fn redact_value(input: &str, secret_values: &[String]) -> String {
    if contains_sensitive_marker(input) {
        return "[redacted]".to_string();
    }
    mask_secret_values(input, secret_values)
}

/// Mask every occurrence of each known secret value in `input`, leaving the rest
/// of the string intact. Unlike [`redact_value`] this never wholesale-redacts on
/// a marker: it only scrubs the literal secret values it is handed.
///
/// Secrets are processed longest-first so a shorter secret that is a substring of
/// a longer one cannot shadow it (which would leave the longer secret's tail
/// exposed). For each secret both the raw value and its query-percent-encoded
/// form are masked: a target that echoes a secret back as we put it on the wire
/// (percent-encoded in a query component) would otherwise leak it. Other server
/// re-encodings (base64, HTML entities) are out of scope by design — we only
/// reverse the encoding WireSurge itself applies.
pub fn mask_secret_values(input: &str, secret_values: &[String]) -> String {
    // Longest-first: see the doc-comment — a shorter prefix must not mask before
    // its superstring, or the superstring's tail leaks through.
    let mut secrets: Vec<&String> = secret_values.iter().filter(|s| !s.is_empty()).collect();
    secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    let mut out = input.to_string();
    for secret in secrets {
        // `String::replace` already scans the whole string, so a `contains`
        // pre-check would only duplicate that work.
        out = out.replace(secret.as_str(), "[redacted]");
        let encoded = query_percent_encode(secret);
        if encoded != *secret.as_str() {
            out = out.replace(&encoded, "[redacted]");
        }
    }
    out
}

/// Percent-encode `input` the way the `url` crate encodes a query component:
/// controls (`< 0x20`), space, `"`, `#`, `<`, `>`, and any non-ASCII byte
/// (`>= 0x80`) become `%XX` (uppercase hex); everything else is copied verbatim.
/// Hand-rolled to avoid a dependency.
fn query_percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        let needs_encoding =
            !(0x20..0x80).contains(&byte) || matches!(byte, b' ' | b'"' | b'#' | b'<' | b'>');
        if needs_encoding {
            out.push('%');
            out.push(nibble_to_hex(byte >> 4));
            out.push(nibble_to_hex(byte & 0x0f));
        } else {
            out.push(byte as char);
        }
    }
    out
}

fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

fn contains_sensitive_marker(input: &str) -> bool {
    let normalized = input.to_ascii_lowercase();
    [
        "authorization",
        "token",
        "secret",
        "password",
        "api_key",
        "apikey",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

pub fn schema_for(resource: &str) -> Result<String> {
    let schema = match resource {
        "workspace" => serde_json::json!({
            "type": "object",
            "description": "WireSurge local workspace metadata",
            "required": ["name", "version"]
        }),
        "request" => serde_json::json!({
            "type": "object",
            "description": "HTTP/API request definition",
            "required": ["name", "url"],
            "properties": ["id", "name", "method", "url", "headers", "body"]
        }),
        "environment" => serde_json::json!({
            "type": "object",
            "description": "Named variables and secret references"
        }),
        "scenario" => serde_json::json!({
            "type": "object",
            "description": "Chained API scenario: profiles, secrets, and an ordered list of protocol-tagged steps with templated requests, response assertions, value extraction, and poll-until-condition loops",
            "required": ["name", "steps"]
        }),
        "run" => serde_json::json!({
            "type": "object",
            "description": "Execution result with request/response metrics and warnings"
        }),
        "report" => serde_json::json!({
            "type": "object",
            "description": "Redacted local run report summary"
        }),
        "runner" => serde_json::json!({
            "type": "object",
            "description": "Local runner heartbeat and worker stats"
        }),
        other => Err(WireSurgeError::new(
            "unknown_schema",
            format!("unknown schema resource '{other}'"),
        )
        .with_hint("Use one of: workspace, request, environment, scenario, run, report, runner"))?,
    };
    serialize_json(&schema)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_json() {
        let request = RequestSpec::from_json(
            r#"{"name":"List Users","method":"get","url":"http://localhost/users","headers":{"X-Test":"yes"}}"#,
        )
        .expect("request parses");
        assert_eq!(request.method, "GET");
        assert_eq!(request.headers.get("x-test"), Some(&"yes".to_string()));
    }

    #[test]
    fn round_trips_simple_yaml() {
        let request =
            RequestSpec::from_json(r#"{"id":"req-a","name":"A","url":"http://localhost"}"#)
                .unwrap();
        let yaml = request.to_yaml().unwrap();
        let parsed = RequestSpec::from_yaml(&yaml).unwrap();
        assert_eq!(parsed.id, "req-a");
        assert_eq!(parsed.url, "http://localhost");
    }

    #[test]
    fn preserves_request_body_exactly() {
        let request = RequestSpec::from_json(
            r#"{"name":"A","url":"http://localhost","body":"{\"value\":1/*literal*/}"}"#,
        )
        .unwrap();
        assert_eq!(request.body.as_deref(), Some(r#"{"value":1/*literal*/}"#));
    }

    #[test]
    fn rejects_invalid_json_numbers() {
        let error = RequestSpec::from_json(r#"{"name":"A","url":"http://localhost","body":01}"#)
            .unwrap_err();
        assert_eq!(error.code, "invalid_json");
    }

    #[test]
    fn preserves_missing_field_error_contract() {
        let error = RequestSpec::from_json(r#"{"url":"http://localhost"}"#).unwrap_err();
        assert_eq!(error.code, "invalid_request");
        assert_eq!(error.path.as_deref(), Some("name"));
    }

    #[test]
    fn mask_secret_values_longest_first_no_tail_leak() {
        // "abc" is a prefix of "abcdef"; without longest-first ordering, masking
        // "abc" first would leave "def" exposed.
        let secrets = vec!["abc".to_string(), "abcdef".to_string()];
        let masked = mask_secret_values("value=abcdef", &secrets);
        assert_eq!(masked, "value=[redacted]");
        assert!(!masked.contains("def"), "{masked}");
    }

    #[test]
    fn mask_secret_values_masks_percent_encoded_form() {
        // A secret containing a space goes on the wire as %20 in a query; mask the
        // encoded form when the target echoes it back that way.
        let secrets = vec!["a b".to_string()];
        let masked = mask_secret_values("echo=a%20b", &secrets);
        assert_eq!(masked, "echo=[redacted]");
        // The raw form is masked too.
        assert_eq!(mask_secret_values("echo=a b", &secrets), "echo=[redacted]");
    }

    #[test]
    fn mask_secret_values_empty_secret_is_noop() {
        let secrets = vec![String::new()];
        assert_eq!(mask_secret_values("unchanged", &secrets), "unchanged");
    }
}
