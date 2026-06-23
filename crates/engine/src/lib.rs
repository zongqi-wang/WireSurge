use std::path::PathBuf;

pub mod load;

use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;
use wiresurge_core::scenario::{Expect, RunSpec, Scope, evaluate};
use wiresurge_core::{
    RequestSpec, Result, WireSurgeError, generate_id, mask_secret_values, serialize_json,
};
use wiresurge_http::{HttpResponse, send_http_request};
use wiresurge_metrics::{ReportSummary, RunnerStats};
use wiresurge_storage::WorkspaceStore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOptions {
    pub parallel: usize,
    pub fail_fast: bool,
    pub dry_run: bool,
    pub verbose: bool,
    pub report_dir: Option<PathBuf>,
    /// Secret values injected into the request via templating. Masked wherever
    /// the request is serialized, since the marker heuristic cannot recognize an
    /// arbitrary credential.
    pub secret_values: Vec<String>,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            parallel: 1,
            fail_fast: false,
            dry_run: false,
            verbose: false,
            report_dir: None,
            secret_values: Vec::new(),
        }
    }
}

/// Outcome of an optional `expect:` assertion. `NotEvaluated` when the run
/// carried no assertion or could not assert (e.g. a dry run with no response);
/// `Passed` when it held; `Failed(_)` when it did not. A failed assertion drives
/// a nonzero CLI exit without being a transport error (the request itself
/// succeeded).
#[derive(Debug, Clone, PartialEq)]
pub enum AssertionOutcome {
    NotEvaluated,
    Passed,
    Failed(WireSurgeError),
}

impl AssertionOutcome {
    /// Serialize to the wire shape shared by [`RunResult::to_json`] and the
    /// persisted report `details`: `null` when not evaluated, `{"passed":true}`
    /// on success, `{"passed":false,"error":..}` on failure.
    fn to_json_value(&self) -> serde_json::Value {
        match self {
            AssertionOutcome::NotEvaluated => serde_json::Value::Null,
            AssertionOutcome::Passed => serde_json::json!({ "passed": true }),
            AssertionOutcome::Failed(error) => {
                serde_json::json!({ "passed": false, "error": error })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RunResult {
    pub id: String,
    pub request: RequestSpec,
    pub response: Option<HttpResponse>,
    pub runner: RunnerStats,
    pub report: Option<ReportSummary>,
    pub warnings: Vec<String>,
    pub dry_run: bool,
    /// Outcome of an optional `expect:` assertion.
    pub assertion: AssertionOutcome,
    /// Secret values to mask when this result is serialized.
    pub secret_values: Vec<String>,
}

impl RunResult {
    /// True when an assertion was evaluated and failed.
    pub fn assertion_failed(&self) -> bool {
        matches!(self.assertion, AssertionOutcome::Failed(_))
    }

    pub fn to_json(&self) -> Result<String> {
        let response = self
            .response
            .as_ref()
            .map(|response| response.to_json_value_with(&self.secret_values))
            .transpose()?;
        let report = self
            .report
            .as_ref()
            .map(ReportSummary::to_json_value)
            .transpose()?;
        let assertion = self.assertion.to_json_value();
        serialize_json(&serde_json::json!({
            "id": self.id,
            "dry_run": self.dry_run,
            "request": self.request.to_json_value_with(&self.secret_values)?,
            "response": response,
            "runner": self.runner,
            "report": report,
            "assertion": assertion,
            "warnings": self.warnings,
        }))
    }
}

/// The HTTP send plus base runner stats for one request, computed *before* any
/// assertion has been evaluated. This step deliberately does NOT write the
/// report artifact or the final runner success snapshot: those depend on the
/// assertion verdict, which only the caller knows, so [`run_run_spec_with_cancellation`]
/// finishes them after evaluating `expect:`. The active (in-flight) runner
/// snapshot IS written here so a watcher sees the run start.
struct SendOutcome {
    run_id: String,
    response: HttpResponse,
    /// Base runner stats reflecting only the HTTP status (`status < 400`); the
    /// caller re-derives success once the assertion is known.
    runner: RunnerStats,
    warnings: Vec<String>,
}

async fn send_request_inner(
    store: &WorkspaceStore,
    request: &RequestSpec,
    options: &RunOptions,
    cancellation: CancellationToken,
) -> Result<SendOutcome> {
    let run_id = generate_id("run", &request.id);
    let active_runner = RunnerStats::local(Some(run_id.clone()), options.parallel);
    store.write_runner_snapshot(&active_runner)?;

    let response = tokio::select! {
        _ = cancellation.cancelled() => {
            let mut cancelled_runner = active_runner.clone();
            cancelled_runner.status = "cancelled".to_string();
            cancelled_runner.active_run_id = None;
            store.write_runner_snapshot(&cancelled_runner)?;
            return Err(WireSurgeError::new("run_cancelled", "HTTP run was cancelled"));
        }
        result = send_http_request(request) => result?,
    };
    let transport_ok = response.status_code < 400;
    let runner = active_runner.finish_with_latency(response.duration_ms, transport_ok);

    let mut warnings = response.warnings.clone();
    if options.parallel > 1 {
        warnings.push("parallel execution is accepted by the CLI, but the current scaffold executes one HTTP request per run".to_string());
    }
    if options.fail_fast {
        warnings.push("fail-fast is enabled; multi-step workflows will stop on first failure once workflow execution is added".to_string());
    }
    if options.verbose {
        warnings.push("verbose diagnostics enabled; sensitive values remain redacted".to_string());
    }

    Ok(SendOutcome {
        run_id,
        response,
        runner,
        warnings,
    })
}

/// Run a templated request file (a [`RunSpec`]: request fields plus optional
/// `vars`/`expect`), expanding `{{ }}` templates against `cli_vars`/`cli_secrets`
/// merged over the file's own `vars`, then evaluating any `expect:` assertion
/// against the response. The request itself succeeding and its assertion passing
/// are reported separately: a failed assertion lands in `RunResult.assertion`
/// (not as a transport error), so the CLI can exit nonzero while still emitting
/// the response.
pub async fn run_run_spec_with_cancellation(
    store: &WorkspaceStore,
    spec: RunSpec,
    cli_vars: BTreeMap<String, String>,
    cli_secrets: BTreeMap<String, String>,
    mut options: RunOptions,
    cancellation: CancellationToken,
) -> Result<RunResult> {
    // CLI-supplied vars override the file's own vars of the same name.
    let mut vars = spec.vars.clone();
    vars.extend(cli_vars);
    // The expanded request inlines secret values into its fields; carry them so
    // every serialization of the result masks them.
    options.secret_values = cli_secrets.values().cloned().collect();
    let secret_values = options.secret_values.clone();
    let scope = Scope::new(vars, cli_secrets, 0, 0);
    let request = spec.expand(&scope)?;
    let expect = spec.expect.clone();

    // A dry run sends no traffic, so there is nothing to assert on: report the
    // active runner snapshot and return early. The assertion is left
    // `NotEvaluated`, and (since `expect` is present here) we warn that the
    // declared contract was not checked rather than letting silence read green.
    if options.dry_run {
        let run_id = generate_id("run", &request.id);
        let runner = RunnerStats::local(Some(run_id.clone()), options.parallel);
        store.write_runner_snapshot(&runner)?;
        let mut warnings = vec!["dry run only; no network traffic was sent".to_string()];
        // No response means the assertion stays `NotEvaluated`; present + dry run
        // is the only way that happens, so this implies dry_run without checking it.
        if expect.is_some() {
            warnings.push("expect declared but not evaluated under --dry-run".to_string());
        }
        return Ok(RunResult {
            id: run_id,
            request,
            response: None,
            runner,
            report: None,
            warnings,
            dry_run: true,
            assertion: AssertionOutcome::NotEvaluated,
            secret_values,
        });
    }

    let report_dir = options.report_dir.clone();
    let SendOutcome {
        run_id,
        response,
        runner,
        warnings,
    } = send_request_inner(store, &request, &options, cancellation).await?;

    // Evaluate the assertion BEFORE recording the run as healthy: a 2xx that
    // fails an assertion must not persist as a successful run, and the report
    // details must carry the verdict.
    let assertion = evaluate_expect(expect.as_ref(), &response, &secret_values);

    // Success now folds in the assertion: transport OK *and* the assertion did
    // not fail. `finish_with_latency` already set base stats from the status; if
    // a passing-status response failed its assertion, downgrade the error rate.
    let transport_ok = response.status_code < 400;
    let success = transport_ok && !matches!(assertion, AssertionOutcome::Failed(_));
    let mut runner = runner;
    if !success {
        runner.error_rate = 1.0;
    }
    store.write_runner_snapshot(&runner)?;

    // The report is the durable record; its body redaction is computed once
    // here (not duplicated) and its `details` carries the same assertion shape
    // as `RunResult::to_json`.
    let report = if let Some(report_dir) = report_dir {
        let report = ReportSummary::single_request(
            generate_id("report", &request.id),
            response.duration_ms,
            success,
        );
        let details = serialize_json(&serde_json::json!({
            "run_id": run_id,
            "request": request.to_json_value_with(&secret_values)?,
            "response": response.to_json_value_with(&secret_values)?,
            "runner": runner,
            "assertion": assertion.to_json_value(),
        }))?;
        store.write_report(&report_dir, &report, &details)?;
        Some(report)
    } else {
        None
    };

    Ok(RunResult {
        id: run_id,
        request,
        response: Some(response),
        runner,
        report,
        warnings,
        dry_run: false,
        assertion,
        secret_values,
    })
}

/// Evaluate an optional assertion against a completed response. Returns
/// `NotEvaluated` when there is no assertion. Any injected secret value is
/// masked in a failure message, which can otherwise echo a templated request
/// value back to the caller; the masking reuses the shared core helper so the
/// longest-first ordering matches `redact_value` exactly.
fn evaluate_expect(
    expect: Option<&Expect>,
    response: &HttpResponse,
    secret_values: &[String],
) -> AssertionOutcome {
    let Some(expect) = expect else {
        return AssertionOutcome::NotEvaluated;
    };
    match evaluate(expect, &response.to_call_response(), secret_values) {
        Ok(()) => AssertionOutcome::Passed,
        Err(mut error) => {
            error.message = mask_secret_values(&error.message, secret_values);
            AssertionOutcome::Failed(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiresurge_core::scenario::{BodyEq, Expect, Selector};

    fn response(status_code: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status_code,
            reason: "OK".to_string(),
            headers: BTreeMap::new(),
            body: body.to_string(),
            duration_ms: 1.0,
            warnings: Vec::new(),
        }
    }

    fn body_eq(value: serde_json::Value) -> Expect {
        Expect {
            status: None,
            body_eq: Some(BodyEq {
                selector: Selector::BodyPointer("/token".to_string()),
                value,
                raw: "body:token".to_string(),
            }),
        }
    }

    #[test]
    fn no_expect_is_not_evaluated() {
        let outcome = evaluate_expect(None, &response(200, "{}"), &[]);
        assert_eq!(outcome, AssertionOutcome::NotEvaluated);
    }

    #[test]
    fn matching_expect_passes() {
        let expect = Expect {
            status: Some(vec![200]),
            body_eq: None,
        };
        let outcome = evaluate_expect(Some(&expect), &response(200, "{}"), &[]);
        assert_eq!(outcome, AssertionOutcome::Passed);
    }

    #[test]
    fn failing_assertion_on_2xx_drives_failure_and_unhealthy_success() {
        // A 2xx response that violates the assertion: transport looks fine, but
        // the run is NOT healthy — success must fold in the assertion verdict.
        let resp = response(200, "{\"token\":\"actual\"}");
        let expect = body_eq(serde_json::json!("expected"));
        let outcome = evaluate_expect(Some(&expect), &resp, &[]);
        assert!(matches!(outcome, AssertionOutcome::Failed(_)));

        let transport_ok = resp.status_code < 400;
        let success = transport_ok && !matches!(outcome, AssertionOutcome::Failed(_));
        assert!(transport_ok, "status 200 should look transport-healthy");
        assert!(
            !success,
            "a 2xx that fails its assertion must not be healthy"
        );
    }

    #[test]
    fn failure_message_masks_secret_value() {
        // The actual value echoed into a body_eq failure message is a secret; it
        // must be masked rather than leaked back to the caller.
        let resp = response(200, "{\"token\":\"s3cr3t-value\"}");
        let expect = body_eq(serde_json::json!("expected"));
        let secrets = vec!["s3cr3t-value".to_string()];
        let outcome = evaluate_expect(Some(&expect), &resp, &secrets);
        match outcome {
            AssertionOutcome::Failed(error) => {
                assert!(
                    !error.message.contains("s3cr3t-value"),
                    "secret leaked in assertion failure message: {}",
                    error.message
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn assertion_outcome_json_shapes_match_contract() {
        assert_eq!(
            AssertionOutcome::NotEvaluated.to_json_value(),
            serde_json::Value::Null
        );
        assert_eq!(
            AssertionOutcome::Passed.to_json_value(),
            serde_json::json!({ "passed": true })
        );
        let error = WireSurgeError::new("assertion_failed", "boom");
        let value = AssertionOutcome::Failed(error.clone()).to_json_value();
        assert_eq!(value["passed"], serde_json::json!(false));
        assert_eq!(value["error"], serde_json::to_value(&error).unwrap());
    }

    #[test]
    fn run_result_json_carries_assertion_verdict() {
        let result = RunResult {
            id: "run-1".to_string(),
            request: RequestSpec {
                id: "req-1".to_string(),
                name: "demo".to_string(),
                method: "GET".to_string(),
                url: "https://example.test/".to_string(),
                headers: BTreeMap::new(),
                body: None,
            },
            response: None,
            runner: RunnerStats::local(Some("run-1".to_string()), 1),
            report: None,
            warnings: Vec::new(),
            dry_run: false,
            assertion: AssertionOutcome::Failed(WireSurgeError::new("assertion_failed", "boom")),
            secret_values: Vec::new(),
        };
        let json: serde_json::Value = serde_json::from_str(&result.to_json().unwrap()).unwrap();
        assert_eq!(json["assertion"]["passed"], serde_json::json!(false));
        assert!(result.assertion_failed());
    }
}
