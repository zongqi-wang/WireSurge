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

use crate::{
    RequestSpec, RequestSpecInput, Result, WireSurgeError, deserialization_error, redact_value,
};

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
    /// Response headers. Keys MUST be stored lowercase: [`Selector::Header`]
    /// lowercases the lookup name, so every protocol adapter's
    /// `to_call_response` is responsible for normalizing header keys to
    /// lowercase on ingest (a mixed-case key would be unreachable).
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
    /// Wall-clock millis captured once at construction; the `{{uuid}}` prefix.
    created_millis: u128,
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
            created_millis: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_millis())
                .unwrap_or_default(),
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

    /// A fresh value for each `{{uuid}}`. Uniqueness holds WITHIN a scope (the
    /// per-scope counter advances every call) and ACROSS workers/iterations of a
    /// run (the `worker_id`/`iteration` fields differ). It does NOT guarantee
    /// cross-process uniqueness: two separate processes constructing a scope in
    /// the same millisecond with worker 0 / iteration 0 produce the same prefix
    /// and would collide. The millis are captured once at [`Scope::new`] rather
    /// than per call, so the value is cheap and stable within the scope.
    fn next_uuid(&self) -> String {
        let counter = self.uuid_counter.fetch_add(1, Ordering::Relaxed);
        format!(
            "{:x}-{:x}-{:x}-{counter:x}",
            self.created_millis, self.worker_id, self.iteration
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

/// Expand `{{ key }}` placeholders in `input` against `scope`. Two escapes let a
/// template emit characters that would otherwise be special:
/// - `\{{` emits a literal `{{` (the template opener).
/// - `\\` emits a single literal `\`, so `\\{{k}}` is a literal backslash
///   followed by the EXPANDED value of `{{k}}` (without this, a literal
///   backslash immediately before a template would be impossible).
///
/// An unterminated `{{` is an error. No regex, no allocation beyond the output
/// string.
pub fn expand(input: &str, scope: &Scope) -> Result<String> {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            // Escaped opener: `\{{` emits a literal `{{`.
            if input[index + 1..].starts_with("{{") {
                out.push_str("{{");
                index += 3;
                continue;
            }
            // Escaped backslash: `\\` emits one literal `\`. This lets a literal
            // backslash sit directly before a template (`\\{{k}}`).
            if input[index + 1..].starts_with('\\') {
                out.push('\\');
                index += 2;
                continue;
            }
            // A lone trailing/other `\` is a literal backslash; fall through to
            // the bulk literal copy below, which will include it in the run.
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
        // Bulk-copy the literal run up to the next `{{` opener or `\` escape, so a
        // long literal segment is one `push_str` rather than one push per char.
        let literal = &input[index..];
        let next = literal
            .char_indices()
            .skip(1)
            .find(|(offset, _)| {
                let tail = &literal[*offset..];
                tail.starts_with("{{") || tail.starts_with('\\')
            })
            .map(|(offset, _)| offset)
            .unwrap_or(literal.len());
        out.push_str(&literal[..next]);
        index += next;
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
            Selector::BodyPointer(pointer) => {
                serde_json::from_str::<serde_json::Value>(&response.body)
                    .ok()
                    .and_then(|value| value.pointer(pointer).cloned())
            }
        }
    }
}

fn invalid_selector(spec: &str, why: &str) -> WireSurgeError {
    WireSurgeError::new(
        "invalid_selector",
        format!("invalid selector '{spec}': {why}"),
    )
    .at(spec.to_string())
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
/// `assertion_failed` error on the first mismatch (fail-fast). `secret_values`
/// holds the run's secret values so a marker-less injected secret echoed in the
/// body cannot leak through a `body_eq` failure message.
pub fn evaluate(expect: &Expect, response: &CallResponse, secret_values: &[String]) -> Result<()> {
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
            Some(actual) if values_match(&actual, &body_eq.value) => {}
            Some(actual) => {
                // `actual` comes straight from the response body, which is
                // redacted elsewhere; redact it here too so a failure message
                // does not echo a credential the body view masks.
                return Err(assertion_failed(format!(
                    "expected {} to equal {}, got {}",
                    body_eq.raw,
                    body_eq.value,
                    redact_value(&actual.to_string(), secret_values)
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

/// Compare an expected value against one resolved from a response. JSON numbers
/// compare by numeric value, so a body that serializes an integer as `5.0`
/// still matches an expected `5`; integers compare losslessly (an `f64` bridge
/// would alias distinct values above 2^53). Every other type compares
/// structurally.
fn values_match(actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
    if let (Some(a), Some(b)) = (actual.as_i64(), expected.as_i64()) {
        return a == b;
    }
    if let (Some(a), Some(b)) = (actual.as_u64(), expected.as_u64()) {
        return a == b;
    }
    if let (Some(a), Some(b)) = (actual.as_f64(), expected.as_f64()) {
        return a == b;
    }
    actual == expected
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
            WireSurgeError::new("invalid_json", error.to_string()).at(format!(
                "line {}, column {}",
                error.line(),
                error.column()
            ))
        })?;
        parsed.into_run_spec()
    }

    /// Lift a stored [`RequestSpec`] into a [`RunSpec`] with no templating
    /// variables and no assertion — the shape `wiresurge run` uses when running a
    /// saved request as-is.
    pub fn from_request(request: RequestSpec) -> RunSpec {
        RunSpec {
            id: request.id,
            name: request.name,
            method: request.method,
            url: request.url,
            headers: request.headers,
            body: request.body,
            vars: BTreeMap::new(),
            expect: None,
        }
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
    // `flatten` forbids `deny_unknown_fields`, so a mistyped top-level key (e.g.
    // `expct:`) would otherwise be silently dropped — a false-green assertion.
    // Catch the leftovers here and reject them in `into_run_spec`.
    #[serde(flatten)]
    unknown: BTreeMap<String, serde_json::Value>,
}

impl RunSpecInput {
    fn into_run_spec(self) -> Result<RunSpec> {
        if let Some(field) = self.unknown.keys().next() {
            return Err(
                WireSurgeError::new("invalid_request", format!("unknown field '{field}'"))
                    .at(field.to_string()),
            );
        }
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
struct ExpectInput {
    #[serde(default)]
    status: Option<StatusInput>,
    #[serde(default)]
    body_eq: Option<BodyEqInput>,
    // Match the top-level `RunSpecInput` taxonomy: capture (rather than
    // `deny_unknown_fields`-reject) an unknown nested key so it surfaces as an
    // `invalid_request` with a field path, not a raw `invalid_yaml` parse error.
    #[serde(flatten)]
    unknown: BTreeMap<String, serde_json::Value>,
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
        if let Some(field) = self.unknown.keys().next() {
            return Err(
                WireSurgeError::new("invalid_request", format!("unknown field '{field}'"))
                    .at(field.to_string()),
            );
        }
        // An empty `status: []` accepts nothing — `[].contains(status)` would
        // reject every response. Reject it at parse rather than silently
        // dropping it (which would let a mistyped `status: []` alongside a
        // `body_eq` pass unnoticed) or failing every run.
        let status = match self.status {
            Some(StatusInput::One(code)) => Some(vec![code]),
            Some(StatusInput::Many(codes)) => {
                if codes.is_empty() {
                    return Err(WireSurgeError::new(
                        "invalid_expect",
                        "expect 'status' must list at least one accepted code",
                    )
                    .at("expect.status"));
                }
                Some(codes)
            }
            None => None,
        };
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
        assert!(evaluate(&expect, &response, &[]).is_ok());

        let expect = Expect {
            status: Some(vec![200]),
            body_eq: None,
        };
        let error = evaluate(&expect, &response, &[]).unwrap_err();
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
        assert!(evaluate(&expect, &response, &[]).is_ok());

        let expect = Expect {
            status: None,
            body_eq: Some(BodyEq {
                selector: Selector::parse("body:status").unwrap(),
                value: serde_json::json!("PENDING"),
                raw: "body:status".to_string(),
            }),
        };
        assert_eq!(
            evaluate(&expect, &response, &[]).unwrap_err().code,
            "assertion_failed"
        );
    }

    #[test]
    fn run_spec_parses_flat_request_unchanged() {
        // A plain request file (no vars/expect) still parses — backward compatible.
        let spec =
            RunSpec::from_yaml("id: req-a\nname: A\nmethod: get\nurl: http://localhost/health\n")
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
        // An unknown nested key under `expect:` now matches the top-level
        // taxonomy: `invalid_request` with a field path (not a raw parse error).
        let error = RunSpec::from_yaml("id: r\nname: r\nurl: http://x\nexpect:\n  stat: 200\n")
            .unwrap_err();
        assert_eq!(error.code, "invalid_request");
        assert_eq!(error.path.as_deref(), Some("stat"));
    }

    #[test]
    fn run_spec_rejects_unknown_top_level_field() {
        // A mistyped `expct:` must not be silently dropped (which would skip the
        // assertion and exit 0) — `flatten` would otherwise swallow it.
        let error = RunSpec::from_yaml("id: r\nname: r\nurl: http://x\nexpct:\n  status: 200\n")
            .unwrap_err();
        assert_eq!(error.code, "invalid_request");
        assert_eq!(error.path.as_deref(), Some("expct"));
    }

    #[test]
    fn evaluate_body_eq_matches_int_and_float() {
        let response = CallResponse::with_status(200, r#"{"count":5.0}"#);
        let expect = Expect {
            status: None,
            body_eq: Some(BodyEq {
                selector: Selector::parse("body:/count").unwrap(),
                value: serde_json::json!(5),
                raw: "body:/count".to_string(),
            }),
        };
        assert!(evaluate(&expect, &response, &[]).is_ok());
    }

    #[test]
    fn evaluate_body_eq_distinguishes_large_integers() {
        // Two distinct u64 values above 2^53 must not alias through an f64.
        let response = CallResponse::with_status(200, r#"{"id":9007199254740993}"#);
        let expect = Expect {
            status: None,
            body_eq: Some(BodyEq {
                selector: Selector::parse("body:/id").unwrap(),
                value: serde_json::json!(9007199254740992u64),
                raw: "body:/id".to_string(),
            }),
        };
        assert_eq!(
            evaluate(&expect, &response, &[]).unwrap_err().code,
            "assertion_failed"
        );
    }

    #[test]
    fn evaluate_body_eq_redacts_marker_value_in_failure() {
        let response = CallResponse::with_status(200, r#"{"token":"live-secret"}"#);
        let expect = Expect {
            status: None,
            body_eq: Some(BodyEq {
                selector: Selector::parse("body:/token").unwrap(),
                value: serde_json::json!("x"),
                raw: "body:/token".to_string(),
            }),
        };
        let error = evaluate(&expect, &response, &[]).unwrap_err();
        assert_eq!(error.code, "assertion_failed");
        assert!(!error.message.contains("live-secret"), "{}", error.message);
    }

    #[test]
    fn evaluate_body_eq_redacts_marker_less_secret_when_supplied() {
        // The secret value carries no marker word, so only the secret_values list
        // can scrub it — proving the new parameter is wired through.
        let response = CallResponse::with_status(200, r#"{"v":"hunter2zz"}"#);
        let expect = Expect {
            status: None,
            body_eq: Some(BodyEq {
                selector: Selector::parse("body:/v").unwrap(),
                value: serde_json::json!("x"),
                raw: "body:/v".to_string(),
            }),
        };
        let secrets = vec!["hunter2zz".to_string()];
        let masked = evaluate(&expect, &response, &secrets).unwrap_err();
        assert!(!masked.message.contains("hunter2zz"), "{}", masked.message);
        // With no secret list the marker-less value passes through (so the test
        // really exercises the parameter, not some other redaction path).
        let leaked = evaluate(&expect, &response, &[]).unwrap_err();
        assert!(leaked.message.contains("hunter2zz"), "{}", leaked.message);
    }

    #[test]
    fn expect_rejects_empty_status_list() {
        // `status: []` accepts no codes; it must be rejected, not silently fail
        // every response.
        let error = RunSpec::from_yaml("id: r\nname: r\nurl: http://x\nexpect:\n  status: []\n")
            .unwrap_err();
        assert_eq!(error.code, "invalid_expect");
    }

    #[test]
    fn expect_rejects_empty_status_list_even_with_body_eq() {
        // An empty `status: []` must be flagged even when another check is
        // present, rather than being silently dropped.
        let error = RunSpec::from_yaml(
            "id: r\nname: r\nurl: http://x\nexpect:\n  status: []\n  body_eq:\n    path: \"body:/ok\"\n    value: true\n",
        )
        .unwrap_err();
        assert_eq!(error.code, "invalid_expect");
        assert_eq!(error.path.as_deref(), Some("expect.status"));
    }

    #[test]
    fn run_spec_from_request_lifts_fields() {
        let request = RequestSpec::from_json(
            r#"{"id":"req-x","name":"X","method":"post","url":"http://localhost/x","headers":{"x-a":"b"},"body":"hi"}"#,
        )
        .unwrap();
        let spec = RunSpec::from_request(request);
        assert_eq!(spec.id, "req-x");
        assert_eq!(spec.name, "X");
        assert_eq!(spec.method, "POST");
        assert_eq!(spec.url, "http://localhost/x");
        assert_eq!(spec.headers.get("x-a").map(String::as_str), Some("b"));
        assert_eq!(spec.body.as_deref(), Some("hi"));
        assert!(spec.vars.is_empty());
        assert!(spec.expect.is_none());
    }

    #[test]
    fn run_spec_from_json_round_trips_and_rejects_trailing_data() {
        let spec = RunSpec::from_json(r#"{"id":"r","name":"r","url":"http://x"}"#).unwrap();
        assert_eq!(spec.id, "r");
        // Trailing junk after the JSON object is rejected by `deserializer.end()`.
        let error =
            RunSpec::from_json(r#"{"id":"r","name":"r","url":"http://x"} junk"#).unwrap_err();
        assert_eq!(error.code, "invalid_json");
    }

    #[test]
    fn expand_backslash_escapes() {
        let scope = scope();
        // `\{{x}}` is a literal `{{x}}` (no expansion).
        assert_eq!(expand(r"\{{x}}", &scope).unwrap(), "{{x}}");
        // `\\{{...}}` is a literal backslash followed by the EXPANDED value.
        assert_eq!(
            expand(r"\\{{vars.base}}", &scope).unwrap(),
            r"\http://localhost:8080"
        );
        // `\\` alone is a single literal backslash.
        assert_eq!(expand(r"\\", &scope).unwrap(), r"\");
        // A lone trailing `\` is a literal backslash (must not panic).
        assert_eq!(expand(r"a\", &scope).unwrap(), r"a\");
    }
}
