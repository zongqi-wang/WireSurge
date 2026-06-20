use std::path::PathBuf;

pub mod load;

use wiresurge_core::{RequestSpec, Result, generate_id, json_array, json_object, json_string};
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
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            parallel: 1,
            fail_fast: false,
            dry_run: false,
            verbose: false,
            report_dir: None,
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
}

impl RunResult {
    pub fn to_json(&self) -> String {
        json_object(&[
            ("id", json_string(&self.id)),
            ("dry_run", self.dry_run.to_string()),
            ("request", self.request.to_json()),
            (
                "response",
                self.response
                    .as_ref()
                    .map(HttpResponse::to_json)
                    .unwrap_or_else(|| "null".to_string()),
            ),
            ("runner", self.runner.to_json()),
            (
                "report",
                self.report
                    .as_ref()
                    .map(ReportSummary::to_json)
                    .unwrap_or_else(|| "null".to_string()),
            ),
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

pub fn run_stored_request(
    store: &WorkspaceStore,
    request_id: &str,
    options: RunOptions,
) -> Result<RunResult> {
    let request = store.load_request(request_id)?;
    run_request(store, request, options)
}

pub fn run_request(
    store: &WorkspaceStore,
    request: RequestSpec,
    options: RunOptions,
) -> Result<RunResult> {
    let run_id = generate_id("run", &request.id);
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
        };
        return Ok(result);
    }

    let response = send_http_request(&request)?;
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
        let details = json_object(&[
            ("run_id", json_string(&run_id)),
            ("request", request.to_json()),
            ("response", response.to_json()),
            ("runner", runner.to_json()),
        ]);
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
    })
}
