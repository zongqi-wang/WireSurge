use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub type Result<T> = std::result::Result<T, WireSurgeError>;

#[derive(Debug, Clone, PartialEq, Eq)]
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
        json_object(&[
            ("code", json_string(&self.code)),
            ("message", json_string(&self.message)),
            (
                "path",
                self.path
                    .as_ref()
                    .map(|value| json_string(value))
                    .unwrap_or_else(|| "null".to_string()),
            ),
            (
                "hint",
                self.hint
                    .as_ref()
                    .map(|value| json_string(value))
                    .unwrap_or_else(|| "null".to_string()),
            ),
            ("retryable", self.retryable.to_string()),
        ])
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

#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    pub fn as_object(&self) -> Option<&BTreeMap<String, JsonValue>> {
        match self {
            JsonValue::Object(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn to_json(&self) -> String {
        match self {
            JsonValue::Null => "null".to_string(),
            JsonValue::Bool(value) => value.to_string(),
            JsonValue::Number(value) => value.clone(),
            JsonValue::String(value) => json_string(value),
            JsonValue::Array(values) => {
                let rendered = values
                    .iter()
                    .map(JsonValue::to_json)
                    .collect::<Vec<_>>()
                    .join(",");
                format!("[{rendered}]")
            }
            JsonValue::Object(values) => {
                let rendered = values
                    .iter()
                    .map(|(key, value)| format!("{}:{}", json_string(key), value.to_json()))
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{{{rendered}}}")
            }
        }
    }
}

pub fn parse_json(input: &str) -> Result<JsonValue> {
    let mut parser = JsonParser::new(input);
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.peek().is_some() {
        return Err(
            WireSurgeError::new("invalid_json", "unexpected trailing characters")
                .at(format!("byte {}", parser.pos)),
        );
    }
    Ok(value)
}

struct JsonParser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue> {
        self.skip_ws();
        match self.peek() {
            Some(b'n') => self.parse_literal(b"null", JsonValue::Null),
            Some(b't') => self.parse_literal(b"true", JsonValue::Bool(true)),
            Some(b'f') => self.parse_literal(b"false", JsonValue::Bool(false)),
            Some(b'"') => self.parse_string().map(JsonValue::String),
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            Some(_) => Err(WireSurgeError::new("invalid_json", "expected JSON value")
                .at(format!("byte {}", self.pos))),
            None => Err(WireSurgeError::new(
                "invalid_json",
                "unexpected end of input",
            )),
        }
    }

    fn parse_literal(&mut self, literal: &[u8], value: JsonValue) -> Result<JsonValue> {
        if self.input.get(self.pos..self.pos + literal.len()) == Some(literal) {
            self.pos += literal.len();
            Ok(value)
        } else {
            Err(WireSurgeError::new("invalid_json", "invalid literal")
                .at(format!("byte {}", self.pos)))
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue> {
        self.expect(b'{')?;
        let mut values = BTreeMap::new();
        self.skip_ws();
        if self.consume(b'}') {
            return Ok(JsonValue::Object(values));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            let value = self.parse_value()?;
            values.insert(key, value);
            self.skip_ws();
            if self.consume(b'}') {
                break;
            }
            self.expect(b',')?;
        }
        Ok(JsonValue::Object(values))
    }

    fn parse_array(&mut self) -> Result<JsonValue> {
        self.expect(b'[')?;
        let mut values = Vec::new();
        self.skip_ws();
        if self.consume(b']') {
            return Ok(JsonValue::Array(values));
        }
        loop {
            values.push(self.parse_value()?);
            self.skip_ws();
            if self.consume(b']') {
                break;
            }
            self.expect(b',')?;
        }
        Ok(JsonValue::Array(values))
    }

    fn parse_number(&mut self) -> Result<JsonValue> {
        let start = self.pos;
        self.consume(b'-');
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        if self.consume(b'.') {
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            let _ = self.consume(b'+') || self.consume(b'-');
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let number = std::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| WireSurgeError::new("invalid_json", "invalid number encoding"))?;
        Ok(JsonValue::Number(number.to_string()))
    }

    fn parse_string(&mut self) -> Result<String> {
        self.expect(b'"')?;
        let mut value = String::new();
        while let Some(byte) = self.next() {
            match byte {
                b'"' => return Ok(value),
                b'\\' => {
                    let escaped = self.next().ok_or_else(|| {
                        WireSurgeError::new("invalid_json", "unterminated escape sequence")
                    })?;
                    match escaped {
                        b'"' => value.push('"'),
                        b'\\' => value.push('\\'),
                        b'/' => value.push('/'),
                        b'b' => value.push('\u{0008}'),
                        b'f' => value.push('\u{000c}'),
                        b'n' => value.push('\n'),
                        b'r' => value.push('\r'),
                        b't' => value.push('\t'),
                        b'u' => value.push(self.parse_unicode_escape()?),
                        _ => {
                            return Err(WireSurgeError::new(
                                "invalid_json",
                                "invalid escape sequence",
                            )
                            .at(format!("byte {}", self.pos)));
                        }
                    }
                }
                byte if byte < 0x20 => {
                    return Err(
                        WireSurgeError::new("invalid_json", "control character in string")
                            .at(format!("byte {}", self.pos)),
                    );
                }
                byte => value.push(byte as char),
            }
        }
        Err(WireSurgeError::new("invalid_json", "unterminated string"))
    }

    fn parse_unicode_escape(&mut self) -> Result<char> {
        let start = self.pos;
        let end = self.pos + 4;
        let raw = self
            .input
            .get(start..end)
            .ok_or_else(|| WireSurgeError::new("invalid_json", "short unicode escape"))?;
        self.pos = end;
        let digits = std::str::from_utf8(raw)
            .map_err(|_| WireSurgeError::new("invalid_json", "invalid unicode escape"))?;
        let value = u16::from_str_radix(digits, 16)
            .map_err(|_| WireSurgeError::new("invalid_json", "invalid unicode escape"))?;
        char::from_u32(value as u32)
            .ok_or_else(|| WireSurgeError::new("invalid_json", "invalid unicode scalar"))
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let value = self.peek()?;
        self.pos += 1;
        Some(value)
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: u8) -> Result<()> {
        if self.consume(expected) {
            Ok(())
        } else {
            Err(
                WireSurgeError::new("invalid_json", format!("expected '{}'", expected as char))
                    .at(format!("byte {}", self.pos)),
            )
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestSpec {
    pub id: String,
    pub name: String,
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<String>,
}

impl RequestSpec {
    pub fn from_json(input: &str) -> Result<Self> {
        let value = parse_json(input)?;
        Self::from_json_value(&value)
    }

    pub fn from_json_value(value: &JsonValue) -> Result<Self> {
        let object = value.as_object().ok_or_else(|| {
            WireSurgeError::new("invalid_request", "request JSON must be an object")
        })?;
        let name = required_string(object, "name")?;
        let method = object
            .get("method")
            .and_then(JsonValue::as_str)
            .unwrap_or("GET")
            .to_ascii_uppercase();
        let url = required_string(object, "url")?;
        let id = object
            .get("id")
            .and_then(JsonValue::as_str)
            .map(ToString::to_string)
            .unwrap_or_else(|| generate_id("req", &name));
        let body = object
            .get("body")
            .and_then(JsonValue::as_str)
            .map(strip_jsonc_comments);
        let mut headers = BTreeMap::new();
        if let Some(header_value) = object.get("headers") {
            let header_object = header_value.as_object().ok_or_else(|| {
                WireSurgeError::new("invalid_request", "headers must be an object").at("headers")
            })?;
            for (key, value) in header_object {
                let value = value.as_str().ok_or_else(|| {
                    WireSurgeError::new("invalid_request", "header values must be strings")
                        .at(format!("headers.{key}"))
                })?;
                headers.insert(key.to_ascii_lowercase(), value.to_string());
            }
        }
        let request = Self {
            id,
            name,
            method,
            url,
            headers,
            body,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn from_yaml(input: &str) -> Result<Self> {
        let mut id = None;
        let mut name = None;
        let mut method = None;
        let mut url = None;
        let mut headers = BTreeMap::new();
        let mut body = None;
        let mut in_headers = false;
        let mut in_body = false;
        let mut body_lines = Vec::new();

        for line in input.lines() {
            if in_body {
                if line.starts_with("  ") || line.is_empty() {
                    body_lines.push(line.strip_prefix("  ").unwrap_or(line).to_string());
                    continue;
                }
                in_body = false;
            }

            let trimmed = line.trim_end();
            if trimmed.is_empty() || trimmed.trim_start().starts_with('#') {
                continue;
            }
            if trimmed == "headers:" {
                in_headers = true;
                continue;
            }
            if trimmed == "body: |" {
                in_headers = false;
                in_body = true;
                continue;
            }
            if in_headers && line.starts_with("  ") {
                if let Some((key, value)) = trimmed.trim().split_once(':') {
                    headers.insert(key.trim().to_ascii_lowercase(), unquote(value.trim()));
                }
                continue;
            }
            in_headers = false;
            if let Some((key, value)) = trimmed.split_once(':') {
                let value = unquote(value.trim());
                match key.trim() {
                    "id" => id = Some(value),
                    "name" => name = Some(value),
                    "method" => method = Some(value.to_ascii_uppercase()),
                    "url" => url = Some(value),
                    _ => {}
                }
            }
        }
        if !body_lines.is_empty() {
            body = Some(body_lines.join("\n"));
        }
        let request = Self {
            id: id.ok_or_else(|| {
                WireSurgeError::new("invalid_request", "request YAML missing id").at("id")
            })?,
            name: name.ok_or_else(|| {
                WireSurgeError::new("invalid_request", "request YAML missing name").at("name")
            })?,
            method: method.unwrap_or_else(|| "GET".to_string()),
            url: url.ok_or_else(|| {
                WireSurgeError::new("invalid_request", "request YAML missing url").at("url")
            })?,
            headers,
            body,
        };
        request.validate()?;
        Ok(request)
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

    pub fn to_json(&self) -> String {
        let headers = self
            .headers
            .iter()
            .map(|(key, value)| (key.as_str(), json_string(value)))
            .collect::<Vec<_>>();
        json_object(&[
            ("id", json_string(&self.id)),
            ("name", json_string(&self.name)),
            ("method", json_string(&self.method)),
            ("url", json_string(&redact_sensitive(&self.url))),
            ("headers", json_object(&headers)),
            (
                "body",
                self.body
                    .as_ref()
                    .map(|body| json_string(&redact_sensitive(body)))
                    .unwrap_or_else(|| "null".to_string()),
            ),
        ])
    }

    pub fn to_yaml(&self) -> String {
        let mut output = String::new();
        output.push_str(&format!("id: {}\n", quote_yaml(&self.id)));
        output.push_str(&format!("name: {}\n", quote_yaml(&self.name)));
        output.push_str(&format!("method: {}\n", quote_yaml(&self.method)));
        output.push_str(&format!("url: {}\n", quote_yaml(&self.url)));
        output.push_str("headers:\n");
        for (key, value) in &self.headers {
            output.push_str(&format!("  {key}: {}\n", quote_yaml(value)));
        }
        if let Some(body) = &self.body {
            output.push_str("body: |\n");
            for line in body.lines() {
                output.push_str("  ");
                output.push_str(line);
                output.push('\n');
            }
        }
        output
    }
}

fn required_string(object: &BTreeMap<String, JsonValue>, key: &str) -> Result<String> {
    object
        .get(key)
        .and_then(JsonValue::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| {
            WireSurgeError::new(
                "invalid_request",
                format!("missing required string field '{key}'"),
            )
            .at(key)
        })
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

pub fn json_string(input: &str) -> String {
    let mut output = String::from("\"");
    for char in input.chars() {
        match char {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            char if char.is_control() => output.push_str(&format!("\\u{:04x}", char as u32)),
            char => output.push(char),
        }
    }
    output.push('"');
    output
}

pub fn json_object(entries: &[(&str, String)]) -> String {
    let body = entries
        .iter()
        .map(|(key, value)| format!("{}:{value}", json_string(key)))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{body}}}")
}

pub fn json_array(entries: &[String]) -> String {
    format!("[{}]", entries.join(","))
}

pub fn redact_sensitive(input: &str) -> String {
    let mut output = input.to_string();
    for marker in [
        "authorization",
        "token",
        "secret",
        "password",
        "api_key",
        "apikey",
    ] {
        if output.to_ascii_lowercase().contains(marker) {
            output = "[redacted]".to_string();
            break;
        }
    }
    output
}

pub fn strip_jsonc_comments(input: &str) -> String {
    let mut output = String::new();
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(char) = chars.next() {
        if in_string {
            if char == '"' && !escaped {
                in_string = false;
            }
            output.push(char);
            escaped = char == '\\' && !escaped;
            continue;
        }
        if char == '"' {
            in_string = true;
            output.push(char);
            continue;
        }
        if char == '/' {
            match chars.peek() {
                Some('/') => {
                    chars.next();
                    for next in chars.by_ref() {
                        if next == '\n' {
                            output.push('\n');
                            break;
                        }
                    }
                }
                Some('*') => {
                    chars.next();
                    let mut previous = '\0';
                    for next in chars.by_ref() {
                        if previous == '*' && next == '/' {
                            break;
                        }
                        previous = next;
                    }
                }
                _ => output.push(char),
            }
        } else {
            output.push(char);
        }
        if char != '\\' {
            escaped = false;
        }
    }
    output
}

pub fn schema_for(resource: &str) -> Result<String> {
    match resource {
        "workspace" => Ok(json_object(&[
            ("type", json_string("object")),
            (
                "description",
                json_string("WireSurge local workspace metadata"),
            ),
            (
                "required",
                json_array(&[json_string("name"), json_string("version")]),
            ),
        ])),
        "request" => Ok(json_object(&[
            ("type", json_string("object")),
            ("description", json_string("HTTP/API request definition")),
            (
                "required",
                json_array(&[json_string("name"), json_string("url")]),
            ),
            (
                "properties",
                json_array(&[
                    json_string("id"),
                    json_string("name"),
                    json_string("method"),
                    json_string("url"),
                    json_string("headers"),
                    json_string("body"),
                ]),
            ),
        ])),
        "environment" => Ok(json_object(&[
            ("type", json_string("object")),
            (
                "description",
                json_string("Named variables and secret references"),
            ),
        ])),
        "workflow" => Ok(json_object(&[
            ("type", json_string("object")),
            (
                "description",
                json_string(
                    "YAML workflow with profiles, variables, secrets, flows, assertions, experiments, and safety limits",
                ),
            ),
        ])),
        "run" => Ok(json_object(&[
            ("type", json_string("object")),
            (
                "description",
                json_string("Execution result with request/response metrics and warnings"),
            ),
        ])),
        "report" => Ok(json_object(&[
            ("type", json_string("object")),
            (
                "description",
                json_string("Redacted local run report summary"),
            ),
        ])),
        "runner" => Ok(json_object(&[
            ("type", json_string("object")),
            (
                "description",
                json_string("Local runner heartbeat and worker stats"),
            ),
        ])),
        other => Err(WireSurgeError::new(
            "unknown_schema",
            format!("unknown schema resource '{other}'"),
        )
        .with_hint("Use one of: workspace, request, environment, workflow, run, report, runner")),
    }
}

fn quote_yaml(value: &str) -> String {
    json_string(value)
}

fn unquote(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        trimmed[1..trimmed.len() - 1]
            .replace("\\\"", "\"")
            .replace("\\n", "\n")
    } else {
        trimmed.to_string()
    }
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
        let yaml = request.to_yaml();
        let parsed = RequestSpec::from_yaml(&yaml).unwrap();
        assert_eq!(parsed.id, "req-a");
        assert_eq!(parsed.url, "http://localhost");
    }

    #[test]
    fn strips_jsonc_outside_strings() {
        let input = r#"{"a":"http://x",// remove
"b":1/* remove */}"#;
        let stripped = strip_jsonc_comments(input);
        assert!(stripped.contains("http://x"));
        assert!(!stripped.contains("remove"));
    }
}
