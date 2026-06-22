//! Scenario primitives: a normalized response shape, `{{ }}` templating, response
//! selectors, and assertions — all pure and protocol-blind.
//!
//! These are the shared building blocks of the API-testing and chained-scenario
//! modes. They know nothing about HTTP, DNS, or any transport: every protocol
//! adapter normalizes its result into a [`CallResponse`], and templating /
//! extraction / assertions operate only on that shape and a [`Scope`] variable
//! bag. Nothing here touches the network or the async runtime, so it is directly
//! unit-testable.
//!
//! Increment 1 ships [`CallResponse`], [`Scope`], [`expand`], [`Selector`],
//! [`Expect`]/[`evaluate`], and [`RunSpec`] (a single templated request plus
//! optional `vars`/`expect`, used by `wiresurge run`). The multi-step scenario
//! schema and executor build on these in a later increment.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

use crate::{RequestSpec, RequestSpecInput, Result, WireSurgeError, deserialization_error};

/// A normalized, protocol-blind response. Every protocol adapter (HTTP, DNS,
/// gRPC, …) maps its native result into this one shape, so templating,
/// extraction, and assertions never branch on the protocol.
///
/// `status` is the HTTP status code (`None` for protocols without one); `code`
/// is a protocol-specific numeric result (DNS rcode, gRPC `grpc-status`, a
/// WebSocket close code). `body` is the decoded text body; JSON extraction
/// parses it on demand.
#[derive(Debug, Clone, PartialEq)]
pub struct CallResponse {
    pub status: Option<u16>,
    pub code: Option<i32>,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    pub duration_ms: f64,
    pub warnings: Vec<String>,
}

impl CallResponse {
    /// A bare response carrying only an HTTP status and body — handy for tests
    /// and for adapters that have nothing else to report.
    pub fn with_status(status: u16, body: impl Into<String>) -> Self {
        Self {
            status: Some(status),
            code: None,
            headers: BTreeMap::new(),
            body: body.into(),
            duration_ms: 0.0,
            warnings: Vec::new(),
        }
    }
}

/// The per-worker variable bag a template resolves against. Owns its data; one
/// is built per worker (never shared mutably), so the `uuid` counter is a plain
/// relaxed atomic with no contention.
///
/// Resolution namespaces for a `{{ key }}`:
/// - `vars.<name>`   — profile / CLI variables
/// - `secrets.<name>`— injected secrets (kept out of serialized output)
/// - `worker.id` / `worker.iteration` — per-worker built-ins
/// - `uuid`          — a fresh unique value each occurrence
/// - `<name>` (bare) — a value written by an earlier step's `extract`
///
/// A reference that resolves to nothing is a hard error: a typo must never
/// silently send empty bytes.
#[derive(Debug)]
pub struct Scope {
    vars: BTreeMap<String, String>,
    secrets: BTreeMap<String, String>,
    worker_id: usize,
    iteration: u64,
    extracts: BTreeMap<String, String>,
    uuid_counter: AtomicU64,
}

impl Scope {
    pub fn new(
        vars: BTreeMap<String, String>,
        secrets: BTreeMap<String, String>,
        worker_id: usize,
        iteration: u64,
    ) -> Self {
        Self {
            vars,
            secrets,
            worker_id,
            iteration,
            extracts: BTreeMap::new(),
            uuid_counter: AtomicU64::new(0),
        }
    }

    /// Record a value produced by a step's `extract`, visible to later steps as
    /// a bare `{{ name }}`.
    pub fn set_extract(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.extracts.insert(name.into(), value.into());
    }

    /// Resolve a single template key (the text between `{{` and `}}`, trimmed).
    fn resolve(&self, key: &str) -> Result<String> {
        if key.is_empty() {
            return Err(WireSurgeError::new(
                "empty_template_ref",
                "template contains an empty '{{}}' reference",
            ));
        }
        if key == "uuid" {
            return Ok(self.next_uuid());
        }
        if let Some((namespace, rest)) = key.split_once('.') {
            match namespace {
                "vars" => self.vars.get(rest).cloned().ok_or_else(|| unknown_var(key)),
                "secrets" => self
                    .secrets
                    .get(rest)
                    .cloned()
                    .ok_or_else(|| missing_secret(key)),
                "worker" => match rest {
                    "id" => Ok(self.worker_id.to_string()),
                    "iteration" => Ok(self.iteration.to_string()),
                    _ => Err(unknown_var(key)),
                },
                _ => Err(unknown_var(key)),
            }
        } else {
            // A bare name is an extract from an earlier step.
            self.extracts
                .get(key)
                .cloned()
                .ok_or_else(|| unknown_var(key))
        }
    }

    /// A fresh value, unique across workers and iterations: the run start time
    /// plus this worker/iteration and a per-scope counter, so two workers in the
    /// same millisecond never collide (millisecond-resolution alone would).
    fn next_uuid(&self) -> String {
        let counter = self.uuid_counter.fetch_add(1, Ordering::Relaxed);
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default();
        format!(
            "{millis:x}-{:x}-{:x}-{counter:x}",
            self.worker_id, self.iteration
        )
    }
}

fn unknown_var(key: &str) -> WireSurgeError {
    WireSurgeError::new(
        "unknown_var",
        format!("template references undefined variable '{{{{{key}}}}}'"),
    )
    .at(key.to_string())
    .with_hint("Declare it in vars, pass --var/--secret, or extract it in an earlier step.")
}

fn missing_secret(key: &str) -> WireSurgeError {
    WireSurgeError::new(
        "missing_secret",
        format!("template references secret '{{{{{key}}}}}' that was not provided"),
    )
    .at(key.to_string())
    .with_hint("Pass it with --secret NAME=VALUE; never store secret values in the file.")
}

/// Expand `{{ key }}` placeholders in `input` against `scope`. A literal `{{`
/// is written as `\{{`. An unterminated `{{` is an error. No regex, no
/// allocation beyond the output string.
pub fn expand(input: &str, scope: &Scope) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        // Escaped opener: `\{{` emits a literal `{{`.
        if bytes[index] == b'\\' && input[index + 1..].starts_with("{{") {
            out.push_str("{{");
            index += 3;
            continue;
        }
        if input[index..].starts_with("{{") {
            let rest = &input[index + 2..];
            let end = rest.find("}}").ok_or_else(|| {
                WireSurgeError::new(
                    "template_unterminated",
                    "unterminated '{{' in template (missing closing '}}')",
                )
            })?;
            let key = rest[..end].trim();
            out.push_str(&scope.resolve(key)?);
            index += 2 + end + 2;
            continue;
        }
        // Otherwise copy one whole UTF-8 character.
        let ch = input[index..]
            .chars()
            .next()
            .expect("index points at a char boundary");
        out.push(ch);
        index += ch.len_utf8();
    }
    Ok(out)
}

/// Which part of a [`CallResponse`] a value comes from. Used by assertions (and,
/// later, extraction). Parsed once from a spec string:
/// - `status`            — the HTTP status code
/// - `header:<name>`     — a response header (case-insensitive)
/// - `body:/a/b`         — an RFC 6901 JSON pointer into the body
/// - `body:a.b.0.c`      — dotted sugar, lowered to the pointer `/a/b/0/c`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    Status,
    Header(String),
    BodyPointer(String),
}

impl Selector {
    pub fn parse(spec: &str) -> Result<Self> {
        if spec == "status" {
            return Ok(Selector::Status);
        }
        if let Some(name) = spec.strip_prefix("header:") {
            if name.is_empty() {
                return Err(invalid_selector(spec, "header name is empty"));
            }
            return Ok(Selector::Header(name.to_ascii_lowercase()));
        }
        if let Some(path) = spec.strip_prefix("body:") {
            return Ok(Selector::BodyPointer(lower_path(path)?));
        }
        Err(invalid_selector(
            spec,
            "must be 'status', 'header:<name>', or 'body:<path>'",
        ))
    }

    /// Resolve to a typed JSON value, or `None` when the value is absent (header
    /// missing, body not JSON, or pointer not found). Callers decide whether an
    /// absent value is an error (extraction) or a failed match (assertion).
    pub fn resolve_value(&self, response: &CallResponse) -> Option<serde_json::Value> {
        match self {
            Selector::Status => response.status.map(|status| status.into()),
            Selector::Header(name) => response
                .headers
                .get(name)
                .map(|value| serde_json::Value::String(value.clone())),
            Selector::BodyPointer(pointer) => serde_json::from_str::<serde_json::Value>(
                &response.body,
            )
            .ok()
            .and_then(|value| value.pointer(pointer).cloned()),
        }
    }
}

fn invalid_selector(spec: &str, why: &str) -> WireSurgeError {
    WireSurgeError::new("invalid_selector", format!("invalid selector '{spec}': {why}")).at(
        spec.to_string(),
    )
}

/// Lower a `body:` path to an RFC 6901 JSON pointer. A path already starting
/// with `/` is taken verbatim; otherwise it is dotted sugar (`a.b.0` →
/// `/a/b/0`) with `~`/`/` escaped per RFC 6901.
fn lower_path(path: &str) -> Result<String> {
    if path.is_empty() {
        return Err(invalid_selector("body:", "path is empty"));
    }
    if path.starts_with('/') {
        return Ok(path.to_string());
    }
    let mut pointer = String::with_capacity(path.len() + 1);
    for segment in path.split('.') {
        pointer.push('/');
        pointer.push_str(&segment.replace('~', "~0").replace('/', "~1"));
    }
    Ok(pointer)
}

/// An assertion over a response: an accepted set of status codes and/or a
/// value-equality check on a selected part of the response.
#[derive(Debug, Clone, PartialEq)]
pub struct Expect {
    pub status: Option<Vec<u16>>,
    pub body_eq: Option<BodyEq>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BodyEq {
    pub selector: Selector,
    pub value: serde_json::Value,
    /// The original selector text, for assertion-failure messages.
    pub raw: String,
}

/// Evaluate an assertion against a response. Returns a structured
/// `assertion_failed` error on the first mismatch (fail-fast).
pub fn evaluate(expect: &Expect, response: &CallResponse) -> Result<()> {
    if let Some(codes) = &expect.status {
        match response.status {
            Some(status) if codes.contains(&status) => {}
            Some(status) => {
                return Err(assertion_failed(format!(
                    "expected status in {codes:?}, got {status}"
                )));
            }
            None => {
                return Err(assertion_failed(format!(
                    "expected status in {codes:?}, but the response carries no status code"
                )));
            }
        }
    }
    if let Some(body_eq) = &expect.body_eq {
        match body_eq.selector.resolve_value(response) {
            Some(actual) if actual == body_eq.value => {}
            Some(actual) => {
                return Err(assertion_failed(format!(
                    "expected {} to equal {}, got {actual}",
                    body_eq.raw, body_eq.value
                )));
            }
            None => {
                return Err(assertion_failed(format!(
                    "expected {} to equal {}, but it was absent or the body was not JSON",
                    body_eq.raw, body_eq.value
                )));
            }
        }
    }
    Ok(())
}

fn assertion_failed(message: String) -> WireSurgeError {
    WireSurgeError::new("assertion_failed", message)
}

/// A single request to run, with optional templating variables and an optional
/// assertion. This is the `wiresurge run` file shape: a superset of a flat
/// request (which still parses unchanged), so request fields may contain
/// `{{ }}` templates resolved against `vars` + CLI input before sending.
#[derive(Debug, Clone, PartialEq)]
pub struct RunSpec {
    pub id: String,
    pub name: String,
    /// Raw (possibly templated) request fields; expanded by [`RunSpec::expand`].
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<String>,
    pub vars: BTreeMap<String, String>,
    pub expect: Option<Expect>,
}

impl RunSpec {
    pub fn from_yaml(input: &str) -> Result<Self> {
        let deserializer = yaml_serde::Deserializer::from_str(input);
        let parsed: RunSpecInput = serde_path_to_error::deserialize(deserializer)
            .map_err(|error| deserialization_error("invalid_yaml", error))?;
        parsed.into_run_spec()
    }

    pub fn from_json(input: &str) -> Result<Self> {
        let mut deserializer = serde_json::Deserializer::from_str(input);
        let parsed: RunSpecInput = serde_path_to_error::deserialize(&mut deserializer)
            .map_err(|error| deserialization_error("invalid_json", error))?;
        deserializer.end().map_err(|error| {
            WireSurgeError::new("invalid_json", error.to_string())
                .at(format!("line {}, column {}", error.line(), error.column()))
        })?;
        parsed.into_run_spec()
    }

    /// Expand every templated field against `scope`, then build and validate a
    /// concrete [`RequestSpec`]. Validation runs post-expansion, so a bad
    /// template (e.g. a URL with no scheme) is caught here, not on the wire.
    pub fn expand(&self, scope: &Scope) -> Result<RequestSpec> {
        let method = expand(&self.method, scope)?.to_ascii_uppercase();
        let url = expand(&self.url, scope)?;
        let mut headers = BTreeMap::new();
        for (key, value) in &self.headers {
            headers.insert(key.to_ascii_lowercase(), expand(value, scope)?);
        }
        let body = match &self.body {
            Some(body) => Some(expand(body, scope)?),
            None => None,
        };
        let request = RequestSpec {
            id: self.id.clone(),
            name: self.name.clone(),
            method,
            url,
            headers,
            body,
        };
        request.validate()?;
        Ok(request)
    }
}

#[derive(Deserialize)]
struct RunSpecInput {
    #[serde(flatten)]
    request: RequestSpecInput,
    #[serde(default)]
    vars: BTreeMap<String, String>,
    #[serde(default)]
    expect: Option<ExpectInput>,
}

impl RunSpecInput {
    fn into_run_spec(self) -> Result<RunSpec> {
        // A run file carries an explicit id (it is a saved request), so require
        // id/name/url here rather than synthesizing one. Defer scheme/method
        // validation to post-expansion (the raw fields may be templates).
        let id = self.request.id.ok_or_else(|| missing_field("id"))?;
        if id.trim().is_empty() {
            return Err(WireSurgeError::new("invalid_request", "request id is required").at("id"));
        }
        let name = self.request.name.ok_or_else(|| missing_field("name"))?;
        let url = self.request.url.ok_or_else(|| missing_field("url"))?;
        Ok(RunSpec {
            id,
            name,
            method: self.request.method.unwrap_or_else(|| "GET".to_string()),
            url,
            headers: self.request.headers,
            body: self.request.body,
            vars: self.vars,
            expect: self.expect.map(ExpectInput::into_expect).transpose()?,
        })
    }
}

fn missing_field(field: &'static str) -> WireSurgeError {
    WireSurgeError::new("invalid_request", format!("request is missing '{field}'")).at(field)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectInput {
    #[serde(default)]
    status: Option<StatusInput>,
    #[serde(default)]
    body_eq: Option<BodyEqInput>,
}

/// `status:` accepts a single code or a list of accepted codes.
#[derive(Deserialize)]
#[serde(untagged)]
enum StatusInput {
    One(u16),
    Many(Vec<u16>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyEqInput {
    path: String,
    value: serde_json::Value,
}

impl ExpectInput {
    fn into_expect(self) -> Result<Expect> {
        let status = self.status.map(|status| match status {
            StatusInput::One(code) => vec![code],
            StatusInput::Many(codes) => codes,
        });
        let body_eq = match self.body_eq {
            Some(input) => Some(BodyEq {
                selector: Selector::parse(&input.path)?,
                value: input.value,
                raw: input.path,
            }),
            None => None,
        };
        if status.is_none() && body_eq.is_none() {
            return Err(WireSurgeError::new(
                "invalid_expect",
                "expect must set at least one of 'status' or 'body_eq'",
            )
            .at("expect"));
        }
        Ok(Expect { status, body_eq })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> Scope {
        let mut vars = BTreeMap::new();
        vars.insert("base".to_string(), "http://localhost:8080".to_string());
        let mut secrets = BTreeMap::new();
        secrets.insert("token".to_string(), "s3cr3t".to_string());
        Scope::new(vars, secrets, 7, 3)
    }

    #[test]
    fn expand_substitutes_vars_secrets_and_builtins() {
        let scope = scope();
        assert_eq!(
            expand("{{vars.base}}/x", &scope).unwrap(),
            "http://localhost:8080/x"
        );
        assert_eq!(
            expand("Bearer {{secrets.token}}", &scope).unwrap(),
            "Bearer s3cr3t"
        );
        assert_eq!(
            expand("w{{worker.id}}-i{{worker.iteration}}", &scope).unwrap(),
            "w7-i3"
        );
    }

    #[test]
    fn expand_resolves_extracts_and_uuid() {
        let mut scope = scope();
        scope.set_extract("resource_id", "r-123");
        assert_eq!(
            expand("/resources/{{resource_id}}", &scope).unwrap(),
            "/resources/r-123"
        );
        // Each occurrence is unique.
        let first = expand("{{uuid}}", &scope).unwrap();
        let second = expand("{{uuid}}", &scope).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn expand_rejects_unknown_var() {
        let error = expand("{{vars.nope}}", &scope()).unwrap_err();
        assert_eq!(error.code, "unknown_var");
        assert_eq!(error.path.as_deref(), Some("vars.nope"));
    }

    #[test]
    fn expand_rejects_missing_secret() {
        let error = expand("{{secrets.absent}}", &scope()).unwrap_err();
        assert_eq!(error.code, "missing_secret");
    }

    #[test]
    fn expand_rejects_unterminated() {
        let error = expand("a {{vars.base", &scope()).unwrap_err();
        assert_eq!(error.code, "template_unterminated");
    }

    #[test]
    fn expand_escapes_literal_braces() {
        assert_eq!(
            expand(r"a \{{ literal }} b", &scope()).unwrap(),
            "a {{ literal }} b"
        );
    }

    #[test]
    fn lower_path_handles_pointer_and_dotted() {
        assert_eq!(lower_path("/data/id").unwrap(), "/data/id");
        assert_eq!(lower_path("data.parent.id").unwrap(), "/data/parent/id");
        assert_eq!(lower_path("items.0.id").unwrap(), "/items/0/id");
    }

    #[test]
    fn selector_resolves_status_header_body() {
        let mut response = CallResponse::with_status(200, r#"{"status":"OPERATIONAL","n":5}"#);
        response
            .headers
            .insert("etag".to_string(), "abc".to_string());
        assert_eq!(
            Selector::parse("status").unwrap().resolve_value(&response),
            Some(serde_json::json!(200))
        );
        assert_eq!(
            Selector::parse("header:ETag")
                .unwrap()
                .resolve_value(&response),
            Some(serde_json::json!("abc"))
        );
        assert_eq!(
            Selector::parse("body:status")
                .unwrap()
                .resolve_value(&response),
            Some(serde_json::json!("OPERATIONAL"))
        );
        assert_eq!(
            Selector::parse("body:/n").unwrap().resolve_value(&response),
            Some(serde_json::json!(5))
        );
        assert_eq!(
            Selector::parse("body:missing")
                .unwrap()
                .resolve_value(&response),
            None
        );
    }

    #[test]
    fn evaluate_status_pass_and_fail() {
        let response = CallResponse::with_status(201, "");
        let expect = Expect {
            status: Some(vec![200, 201]),
            body_eq: None,
        };
        assert!(evaluate(&expect, &response).is_ok());

        let expect = Expect {
            status: Some(vec![200]),
            body_eq: None,
        };
        let error = evaluate(&expect, &response).unwrap_err();
        assert_eq!(error.code, "assertion_failed");
    }

    #[test]
    fn evaluate_body_eq() {
        let response = CallResponse::with_status(200, r#"{"status":"OPERATIONAL"}"#);
        let expect = Expect {
            status: None,
            body_eq: Some(BodyEq {
                selector: Selector::parse("body:status").unwrap(),
                value: serde_json::json!("OPERATIONAL"),
                raw: "body:status".to_string(),
            }),
        };
        assert!(evaluate(&expect, &response).is_ok());

        let expect = Expect {
            status: None,
            body_eq: Some(BodyEq {
                selector: Selector::parse("body:status").unwrap(),
                value: serde_json::json!("PENDING"),
                raw: "body:status".to_string(),
            }),
        };
        assert_eq!(
            evaluate(&expect, &response).unwrap_err().code,
            "assertion_failed"
        );
    }

    #[test]
    fn run_spec_parses_flat_request_unchanged() {
        // A plain request file (no vars/expect) still parses — backward compatible.
        let spec = RunSpec::from_yaml(
            "id: req-a\nname: A\nmethod: get\nurl: http://localhost/health\n",
        )
        .unwrap();
        assert_eq!(spec.id, "req-a");
        assert!(spec.vars.is_empty());
        assert!(spec.expect.is_none());
    }

    #[test]
    fn run_spec_parses_vars_and_expect_then_expands() {
        let yaml = r#"
id: req-create
name: Create
method: POST
url: "{{vars.base}}/resources"
headers:
  authorization: "Bearer {{secrets.token}}"
vars:
  base: "http://127.0.0.1:9000"
expect:
  status: [200, 201]
"#;
        let spec = RunSpec::from_yaml(yaml).unwrap();
        let mut vars = spec.vars.clone();
        vars.insert("base".to_string(), "http://127.0.0.1:9000".to_string());
        let mut secrets = BTreeMap::new();
        secrets.insert("token".to_string(), "abc".to_string());
        let scope = Scope::new(vars, secrets, 0, 0);
        let request = spec.expand(&scope).unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.url, "http://127.0.0.1:9000/resources");
        assert_eq!(
            request.headers.get("authorization").map(String::as_str),
            Some("Bearer abc")
        );
        assert!(spec.expect.is_some());
    }

    #[test]
    fn run_spec_expand_validates_post_expansion() {
        // A template that expands to a scheme-less URL is rejected by validate().
        let yaml = "id: r\nname: r\nurl: \"{{vars.base}}/x\"\nvars:\n  base: not-a-url\n";
        let spec = RunSpec::from_yaml(yaml).unwrap();
        let scope = Scope::new(spec.vars.clone(), BTreeMap::new(), 0, 0);
        let error = spec.expand(&scope).unwrap_err();
        assert_eq!(error.code, "invalid_request");
    }

    #[test]
    fn expect_requires_a_check() {
        let error = RunSpec::from_yaml("id: r\nname: r\nurl: http://x\nexpect: {}\n").unwrap_err();
        assert_eq!(error.code, "invalid_expect");
    }

    #[test]
    fn expect_rejects_unknown_field() {
        let error =
            RunSpec::from_yaml("id: r\nname: r\nurl: http://x\nexpect:\n  stat: 200\n").unwrap_err();
        assert_eq!(error.code, "invalid_yaml");
    }
}
