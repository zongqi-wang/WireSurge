use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::thread;
use std::time::Duration;

use wiresurge_core::{
    RequestSpec, Result, WireSurgeError, json_array, json_object, json_string, schema_for,
};
use wiresurge_dns::{DnsRunConfig, DnsTransport, decode_hex_payload, parse_qtype, run_dns};
use wiresurge_engine::{RunOptions, run_request, run_stored_request};
use wiresurge_plugins::PluginManifestDraft;
use wiresurge_storage::WorkspaceStore;

static SIGNAL_CODE: AtomicU8 = AtomicU8::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliOutcome {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CliOutcome {
    fn ok_with_code(stdout: impl Into<String>, code: i32) -> Self {
        Self {
            code,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    fn err(error: WireSurgeError, output_json: bool) -> Self {
        if output_json {
            Self {
                code: 1,
                stdout: json_object(&[("error", error.to_json())]),
                stderr: String::new(),
            }
        } else {
            Self {
                code: 1,
                stdout: String::new(),
                stderr: error.to_string(),
            }
        }
    }
}

pub fn dispatch(args: &[String], cwd: PathBuf) -> CliOutcome {
    let output_json = wants_json_output(args);
    match run(args, cwd, output_json) {
        Ok((stdout, code)) => CliOutcome::ok_with_code(stdout, code),
        Err(error) => CliOutcome::err(error, output_json),
    }
}

fn run(args: &[String], cwd: PathBuf, output_json: bool) -> Result<(String, i32)> {
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
        return Ok((help_text(), 0));
    }
    let store = WorkspaceStore::new(cwd);
    let output = match args[0].as_str() {
        "schema" => {
            let resource = args.get(1).ok_or_else(|| {
                WireSurgeError::new("missing_argument", "schema requires a resource name")
            })?;
            schema_for(resource)
        }
        "dns" => return dns_command(&args[1..], output_json),
        "workspace" => workspace_command(&store, &args[1..], output_json),
        "request" => request_command(&store, &args[1..], output_json),
        "run" => run_command(&store, &args[1..]),
        "runner" => runner_command(&store, &args[1..]),
        "report" => report_command(&store, &args[1..]),
        "secret" => secret_command(&args[1..]),
        "plugin" => plugin_command(&args[1..]),
        other => Err(
            WireSurgeError::new("unknown_command", format!("unknown command '{other}'"))
                .with_hint("Run `wiresurge --help`."),
        ),
    }?;
    Ok((output, 0))
}

fn dns_command(args: &[String], output_json: bool) -> Result<(String, i32)> {
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        return Ok((dns_help_text(), 0));
    }
    let server = args[0].clone();
    let transport = DnsTransport::from_str(option_value(args, "--protocol").unwrap_or("udp"))?;
    let port = parse_number_option(args, "--port", 53_u16)?;
    let count = parse_number_option(args, "--count", 1_u64)?;
    let concurrency = parse_number_option(args, "--concurrency", 1_usize)?;
    let timeout_ms = parse_number_option(args, "--timeout-ms", 2000_u64)?;
    let qps = option_value(args, "--qps")
        .map(|value| {
            value.parse::<f64>().map_err(|_| {
                WireSurgeError::new("invalid_argument", "--qps must be a number").at("qps")
            })
        })
        .transpose()?;
    let edns_payload = option_value(args, "--edns-payload-hex")
        .map(decode_hex_payload)
        .transpose()?;
    let config = DnsRunConfig {
        server,
        port,
        transport,
        qname: option_value(args, "--name")
            .unwrap_or("example.com")
            .to_string(),
        qtype: parse_qtype(option_value(args, "--type").unwrap_or("A"))?,
        count,
        concurrency,
        timeout: Duration::from_millis(timeout_ms),
        qps,
        edns_payload,
    };

    SIGNAL_CODE.store(0, Ordering::Release);
    let _signal_guard = install_signal_handlers()?;
    let cancellation = Arc::new(AtomicBool::new(false));
    let watcher_cancellation = Arc::clone(&cancellation);
    let watcher_done = Arc::new(AtomicBool::new(false));
    let watcher_done_thread = Arc::clone(&watcher_done);
    let signal_watcher = thread::spawn(move || {
        while !watcher_done_thread.load(Ordering::Acquire) {
            if SIGNAL_CODE.load(Ordering::Acquire) != 0 {
                watcher_cancellation.store(true, Ordering::Release);
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    });
    let run_result = run_dns(config, cancellation);
    watcher_done.store(true, Ordering::Release);
    let _ = signal_watcher.join();
    let stats = run_result?;
    let exit_code = match SIGNAL_CODE.load(Ordering::Acquire) {
        130 => 130,
        143 => 143,
        _ if stats.cancelled => 130,
        _ => 0,
    };
    let output = if output_json {
        stats.to_json()
    } else {
        stats.to_text()
    };
    Ok((output, exit_code))
}

#[cfg(unix)]
extern "C" fn unix_signal_handler(signal: i32) {
    let exit_code = if signal == 15 { 143 } else { 130 };
    SIGNAL_CODE.store(exit_code, Ordering::Release);
}

#[cfg(unix)]
unsafe extern "C" {
    fn signal(signal: i32, handler: usize) -> usize;
}

#[cfg(unix)]
fn install_signal_handlers() -> Result<SignalGuard> {
    // The handler only performs an atomic store, keeping work out of signal context.
    unsafe {
        signal(2, unix_signal_handler as *const () as usize);
        signal(15, unix_signal_handler as *const () as usize);
    }
    Ok(SignalGuard)
}

#[cfg(windows)]
unsafe extern "system" fn windows_console_handler(control: u32) -> i32 {
    let exit_code = if control == 0 || control == 1 {
        130
    } else {
        143
    };
    SIGNAL_CODE.store(exit_code, Ordering::Release);
    1
}

#[cfg(windows)]
#[link(name = "Kernel32")]
unsafe extern "system" {
    fn SetConsoleCtrlHandler(
        handler: Option<unsafe extern "system" fn(u32) -> i32>,
        add: i32,
    ) -> i32;
}

#[cfg(windows)]
fn install_signal_handlers() -> Result<SignalGuard> {
    let installed = unsafe { SetConsoleCtrlHandler(Some(windows_console_handler), 1) };
    if installed == 0 {
        Err(WireSurgeError::new(
            "signal_handler_install_failed",
            "failed to install the Windows console control handler",
        ))
    } else {
        Ok(SignalGuard)
    }
}

#[cfg(not(any(unix, windows)))]
fn install_signal_handlers() -> Result<SignalGuard> {
    Ok(SignalGuard)
}

struct SignalGuard;

#[cfg(unix)]
impl Drop for SignalGuard {
    fn drop(&mut self) {
        // SIG_DFL is represented by the null signal-handler pointer.
        unsafe {
            signal(2, 0);
            signal(15, 0);
        }
    }
}

#[cfg(windows)]
impl Drop for SignalGuard {
    fn drop(&mut self) {
        unsafe {
            SetConsoleCtrlHandler(Some(windows_console_handler), 0);
        }
    }
}

#[cfg(not(any(unix, windows)))]
impl Drop for SignalGuard {
    fn drop(&mut self) {}
}

fn parse_number_option<T>(args: &[String], flag: &str, default: T) -> Result<T>
where
    T: FromStr,
{
    match option_value(args, flag) {
        Some(value) => value.parse::<T>().map_err(|_| {
            WireSurgeError::new("invalid_argument", format!("{flag} has an invalid value"))
                .at(flag.trim_start_matches('-'))
        }),
        None => Ok(default),
    }
}

fn workspace_command(store: &WorkspaceStore, args: &[String], output_json: bool) -> Result<String> {
    let action = args.first().map(String::as_str).unwrap_or("show");
    match action {
        "init" => {
            store.init()?;
            let workspace = store.workspace_json()?;
            if output_json {
                Ok(json_object(&[("workspace", workspace)]))
            } else {
                Ok(format!(
                    "Initialized WireSurge workspace at {}",
                    store.root().display()
                ))
            }
        }
        "list" => {
            if store.exists() {
                Ok(json_array(&[store.workspace_json()?]))
            } else {
                Ok("[]".to_string())
            }
        }
        "show" => store.workspace_json(),
        _ => Err(WireSurgeError::new(
            "unknown_workspace_action",
            "workspace action must be init, list, or show",
        )),
    }
}

fn request_command(store: &WorkspaceStore, args: &[String], _output_json: bool) -> Result<String> {
    let action = args
        .first()
        .ok_or_else(|| WireSurgeError::new("missing_argument", "request requires an action"))?;
    match action.as_str() {
        "create" => {
            let input = option_value(args, "--json").ok_or_else(|| {
                WireSurgeError::new("missing_json", "request create requires --json '{...}'")
                    .with_hint("Run `wiresurge schema request` to inspect the accepted shape.")
            })?;
            let request = RequestSpec::from_json(input)?;
            store.create_request(&request)?;
            Ok(json_object(&[("request", request.to_json())]))
        }
        "list" => {
            let requests = store
                .list_requests()?
                .iter()
                .map(RequestSpec::to_json)
                .collect::<Vec<_>>();
            Ok(json_array(&requests))
        }
        "show" => {
            let id = args.get(1).ok_or_else(|| {
                WireSurgeError::new("missing_argument", "request show requires an id")
            })?;
            Ok(store.load_request(id)?.to_json())
        }
        "update" => {
            let id = args.get(1).ok_or_else(|| {
                WireSurgeError::new("missing_argument", "request update requires an id")
            })?;
            let input = option_value(args, "--json").ok_or_else(|| {
                WireSurgeError::new("missing_json", "request update requires --json '{...}'")
                    .with_hint("Run `wiresurge schema request` to inspect the accepted shape.")
            })?;
            let request = RequestSpec::from_json(input)?;
            store.update_request(id, &request)?;
            Ok(json_object(&[(
                "request",
                store.load_request(id)?.to_json(),
            )]))
        }
        "delete" => {
            let id = args.get(1).ok_or_else(|| {
                WireSurgeError::new("missing_argument", "request delete requires an id")
            })?;
            store.delete_request(id)?;
            Ok(json_object(&[("deleted", json_string(id))]))
        }
        _ => Err(WireSurgeError::new(
            "unknown_request_action",
            "request action must be create, list, show, update, or delete",
        )),
    }
}

fn run_command(store: &WorkspaceStore, args: &[String]) -> Result<String> {
    let target = args.first().ok_or_else(|| {
        WireSurgeError::new(
            "missing_argument",
            "run requires a request id or request YAML file",
        )
    })?;
    let options = RunOptions {
        parallel: option_value(args, "--parallel")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1),
        fail_fast: has_flag(args, "--fail-fast"),
        dry_run: has_flag(args, "--dry-run"),
        verbose: has_flag(args, "--verbose"),
        report_dir: option_value(args, "--report").map(PathBuf::from),
    };
    if PathBuf::from(target).exists() {
        let input = fs::read_to_string(target)?;
        let request = RequestSpec::from_yaml(&input)?;
        Ok(run_request(store, request, options)?.to_json())
    } else {
        Ok(run_stored_request(store, target, options)?.to_json())
    }
}

fn runner_command(store: &WorkspaceStore, args: &[String]) -> Result<String> {
    let action = args.first().map(String::as_str).unwrap_or("list");
    match action {
        "list" | "stats" => store.runner_entries_json(),
        _ => Err(WireSurgeError::new(
            "unknown_runner_action",
            "runner action must be list or stats",
        )),
    }
}

fn report_command(store: &WorkspaceStore, args: &[String]) -> Result<String> {
    let action = args.first().map(String::as_str).unwrap_or("list");
    match action {
        "list" => store.report_entries_json(),
        "show" => {
            let id = args
                .get(1)
                .ok_or_else(|| WireSurgeError::new("missing_argument", "report show requires an id"))?;
            store.load_report_summary(id)
        }
        "export" => Err(WireSurgeError::new("not_implemented", "report export is reserved for the report phase")
            .with_hint("Current runs already write summary.json, details.json, and index.html when --report is used.")),
        _ => Err(WireSurgeError::new("unknown_report_action", "report action must be list, show, or export")),
    }
}

fn secret_command(_args: &[String]) -> Result<String> {
    Err(WireSurgeError::new("not_implemented", "keychain-backed secrets are planned for phase 7")
        .with_hint("Do not store real secrets in request files; use placeholder values until the keychain adapter lands."))
}

fn plugin_command(args: &[String]) -> Result<String> {
    let action = args
        .first()
        .map(String::as_str)
        .unwrap_or("manifest-example");
    match action {
        "manifest-example" => Ok(PluginManifestDraft::example().to_json()),
        _ => Err(WireSurgeError::new(
            "unknown_plugin_action",
            "plugin action must be manifest-example",
        )),
    }
}

fn option_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|window| window[0] == flag)
        .map(|window| window[1].as_str())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|arg| arg == flag)
}

fn wants_json_output(args: &[String]) -> bool {
    option_value(args, "--output") == Some("json")
}

fn help_text() -> String {
    r#"WireSurge - local-first programmable traffic workbench

Usage:
  wiresurge schema <workspace|request|environment|workflow|run|report|runner>
  wiresurge dns <server> [--protocol udp|tcp] [--name <domain>] [--type <qtype>] [--count <n>] [--concurrency <n>] [--qps <n>]
  wiresurge workspace init|list|show [--output json]
  wiresurge request create --json '{...}'
  wiresurge request list|show|update|delete
  wiresurge run <request-id|request.yaml> [--output json] [--report <dir>] [--parallel <n>] [--dry-run] [--fail-fast] [--verbose]
  wiresurge runner list|stats [--output json]
  wiresurge report list|show|export
  wiresurge secret set|get|delete
  wiresurge plugin manifest-example

Agent rules:
  - Mutating request commands accept --json and return JSON with stable IDs.
  - Errors are structured with code, message, path, hint, and retryable fields when --output json is set.
  - Non-TTY usage never prompts; use --dry-run and --output json for planning.
"#
    .trim()
    .to_string()
}

fn dns_help_text() -> String {
    r#"WireSurge DNS over UDP/TCP

Usage:
  wiresurge dns <server> [options]

Options:
  --protocol <udp|tcp>       Transport protocol (default: udp)
  --port <port>              Target port (default: 53)
  --name <domain>            Query name (default: example.com)
  --type <qtype>             A, AAAA, NS, CNAME, SOA, PTR, MX, TXT, SRV, ANY, or numeric (default: A)
  --count <n>                Total queries (default: 1)
  --concurrency <n>          Concurrent senders; each owns a UDP socket or TCP connection (default: 1)
  --qps <n>                  Optional global queries-per-second limit
  --timeout-ms <ms>          Per-query timeout (default: 2000)
  --edns-payload-hex <hex>   Add EDNS0 option 65001 with custom bytes
  --output json              Emit machine-readable metrics

Examples:
  wiresurge dns 127.0.0.1 --name example.com
  wiresurge dns 127.0.0.1 --protocol tcp --count 1000 --concurrency 8 --output json
"#
    .trim()
    .to_string()
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "wiresurge-cli-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn help_mentions_schema() {
        let outcome = dispatch(&["--help".to_string()], temp_dir());
        assert_eq!(outcome.code, 0);
        assert!(outcome.stdout.contains("wiresurge schema"));
    }

    #[test]
    fn dns_help_lists_udp_and_tcp() {
        let outcome = dispatch(&["dns".to_string(), "--help".to_string()], temp_dir());
        assert_eq!(outcome.code, 0);
        assert!(outcome.stdout.contains("--protocol <udp|tcp>"));
        assert!(outcome.stdout.contains("--concurrency"));
    }

    #[test]
    fn dns_rejects_invalid_protocol_with_structured_error() {
        let outcome = dispatch(
            &[
                "dns".to_string(),
                "127.0.0.1".to_string(),
                "--protocol".to_string(),
                "invalid".to_string(),
                "--output".to_string(),
                "json".to_string(),
            ],
            temp_dir(),
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome.stdout.contains("invalid_dns_transport"));
    }

    #[test]
    fn creates_and_lists_request_json() {
        let root = temp_dir();
        let init = dispatch(
            &[
                "workspace".into(),
                "init".into(),
                "--output".into(),
                "json".into(),
            ],
            root.clone(),
        );
        assert_eq!(init.code, 0);
        let create = dispatch(
            &[
                "request".into(),
                "create".into(),
                "--json".into(),
                r#"{"id":"req-a","name":"A","url":"http://localhost"}"#.into(),
                "--output".into(),
                "json".into(),
            ],
            root.clone(),
        );
        assert_eq!(create.code, 0, "{}", create.stderr);
        let list = dispatch(
            &[
                "request".into(),
                "list".into(),
                "--output".into(),
                "json".into(),
            ],
            root.clone(),
        );
        assert_eq!(list.code, 0);
        assert!(list.stdout.contains("\"id\":\"req-a\""));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn structured_error_when_workspace_missing() {
        let outcome = dispatch(
            &[
                "request".into(),
                "list".into(),
                "--output".into(),
                "json".into(),
            ],
            temp_dir(),
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome.stdout.contains("\"code\":\"workspace_not_found\""));
    }
}
