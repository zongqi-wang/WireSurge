use std::path::PathBuf;

pub mod load;

use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;
use wiresurge_core::scenario::{Expect, RunSpec, Scope, evaluate};
use wiresurge_core::{RequestSpec, Result, WireSurgeError, generate_id, serialize_json};
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

#[derive(Debug, Clone, PartialEq)]
pub struct RunResult {
    pub id: String,
    pub request: RequestSpec,
    pub response: Option<HttpResponse>,
    pub runner: RunnerStats,
    pub report: Option<ReportSummary>,
    pub warnings: Vec<String>,
    pub dry_run: bool,
    /// Result of an optional `expect:` assertion. `None` when the run carried no
    /// assertion; `Some(Ok(()))` when it passed; `Some(Err(_))` when it failed.
    /// A failed assertion drives a nonzero CLI exit without being a transport
    /// error (the request itself succeeded).
    pub assertion: Option<std::result::Result<(), WireSurgeError>>,
    /// Secret values to mask when this result is serialized.
    pub secret_values: Vec<String>,
}

impl RunResult {
    /// True when an assertion was evaluated and failed.
    pub fn assertion_failed(&self) -> bool {
        matches!(self.assertion, Some(Err(_)))
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
        let assertion = match &self.assertion {
            None => serde_json::Value::Null,
            Some(Ok(())) => serde_json::json!({ "passed": true }),
            Some(Err(error)) => serde_json::json!({ "passed": false, "error": error }),
        };
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

pub async fn run_stored_request(
    store: &WorkspaceStore,
    request_id: &str,
    options: RunOptions,
) -> Result<RunResult> {
    let request = store.load_request(request_id)?;
    run_request(store, request, options).await
}

pub async fn run_stored_request_with_cancellation(
    store: &WorkspaceStore,
    request_id: &str,
    options: RunOptions,
    cancellation: CancellationToken,
) -> Result<RunResult> {
    let request = store.load_request(request_id)?;
    run_request_with_cancellation(store, request, options, cancellation).await
}

pub async fn run_request(
    store: &WorkspaceStore,
    request: RequestSpec,
    options: RunOptions,
) -> Result<RunResult> {
    run_request_with_cancellation(store, request, options, CancellationToken::new()).await
}

pub async fn run_request_with_cancellation(
    store: &WorkspaceStore,
    request: RequestSpec,
    options: RunOptions,
    cancellation: CancellationToken,
) -> Result<RunResult> {
    let run_id = generate_id("run", &request.id);
    let secret_values = options.secret_values.clone();
    let active_runner = RunnerStats::local(Some(run_id.clone()), options.parallel);
    store.write_runner_snapshot(&active_runner)?;

    if options.dry_run {
        let warnings = vec!["dry run only; no network traffic was sent".to_string()];
        let result = RunResult {
            id: run_id,
            request,
            response: None,
            runner: active_runner,
            report: None,
            warnings,
            dry_run: true,
            assertion: None,
            secret_values,
        };
        return Ok(result);
    }

    let response = tokio::select! {
        _ = cancellation.cancelled() => {
            let mut cancelled_runner = active_runner.clone();
            cancelled_runner.status = "cancelled".to_string();
            cancelled_runner.active_run_id = None;
            store.write_runner_snapshot(&cancelled_runner)?;
            return Err(WireSurgeError::new("run_cancelled", "HTTP run was cancelled"));
        }
        result = send_http_request(&request) => result?,
    };
    let success = response.status_code < 400;
    let runner = active_runner.finish_with_latency(response.duration_ms, success);
    store.write_runner_snapshot(&runner)?;

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

    let report = if let Some(report_dir) = options.report_dir {
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
        assertion: None,
        secret_values,
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
    let scope = Scope::new(vars, cli_secrets, 0, 0);
    let request = spec.expand(&scope)?;
    let expect = spec.expect.clone();

    let dry_run = options.dry_run;
    let mut result = run_request_with_cancellation(store, request, options, cancellation).await?;
    result.assertion = evaluate_expect(expect.as_ref(), &result);
    // An assertion that cannot run (no response, e.g. a dry run) would otherwise
    // be indistinguishable from no assertion at all — a false green. Warn so the
    // caller knows the contract was declared but not checked.
    if expect.is_some() && result.assertion.is_none() && dry_run {
        result
            .warnings
            .push("expect declared but not evaluated under --dry-run".to_string());
    }
    Ok(result)
}

/// Evaluate an optional assertion against a completed run. Returns `None` when
/// there is no assertion or no response to assert on (e.g. a dry run). Any
/// injected secret value is masked in a failure message, which can otherwise
/// echo a templated request value back to the caller.
fn evaluate_expect(
    expect: Option<&Expect>,
    result: &RunResult,
) -> Option<std::result::Result<(), WireSurgeError>> {
    let expect = expect?;
    let response = result.response.as_ref()?;
    Some(
        evaluate(expect, &response.to_call_response()).map_err(|mut error| {
            for secret in &result.secret_values {
                if !secret.is_empty() {
                    error.message = error.message.replace(secret.as_str(), "[redacted]");
                }
            }
            error
        }),
    )
}
