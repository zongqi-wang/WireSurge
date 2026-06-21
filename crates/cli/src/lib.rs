use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::thread;
use std::time::Duration;

use std::net::{SocketAddr, ToSocketAddrs};

use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{Args, Parser, Subcommand};
use tokio_util::sync::CancellationToken;
use wiresurge_core::{
    RequestSpec, Result, WireSurgeError, json_array, json_object, json_string, schema_for,
};
use wiresurge_corpus::Corpus;
use wiresurge_dns::{
    DnsRunConfig, DnsTransport, EdnsOption, decode_hex_payload, parse_qtype, run_dns,
};
use wiresurge_engine::load::{LoadConfig, LoadProto, LoadStats, run_load};
use wiresurge_engine::{RunOptions, run_request, run_stored_request};
use wiresurge_plugins::PluginManifestDraft;
use wiresurge_storage::WorkspaceStore;
use wiresurge_transport::{AppProto, ConnectTarget, TlsParams, build_client_config};

static SIGNAL_CODE: AtomicU8 = AtomicU8::new(0);

const DEFAULT_EDNS_CODE: u16 = 65001;

const AFTER_HELP: &str = "Run `wiresurge schema <resource>` to inspect accepted shapes.\n\
Mutating request commands accept --json and return JSON with stable IDs.\n\
Pass --output json for machine-readable output and structured errors; non-TTY usage never prompts.";

#[derive(Parser)]
#[command(
    name = "wiresurge",
    about = "WireSurge - local-first programmable traffic workbench",
    after_help = AFTER_HELP,
    arg_required_else_help = true,
    disable_version_flag = true
)]
struct Cli {
    #[arg(long, global = true, value_name = "json")]
    output: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Schema {
        resource: String,
    },
    #[command(arg_required_else_help = true)]
    Dns(DnsArgs),
    #[command(arg_required_else_help = true)]
    Load(LoadArgs),
    Workspace {
        action: Option<String>,
    },
    Request(RequestArgs),
    Run(RunArgs),
    Runner {
        action: Option<String>,
    },
    Report {
        action: Option<String>,
        id: Option<String>,
    },
    Secret {
        action: Option<String>,
    },
    Plugin {
        action: Option<String>,
    },
}

#[derive(Args)]
struct DnsArgs {
    server: String,
    #[arg(long, value_name = "udp|tcp", default_value = "udp")]
    protocol: String,
    #[arg(long, default_value_t = 53)]
    port: u16,
    #[arg(long, default_value = "example.com")]
    name: String,
    #[arg(long = "type", default_value = "A")]
    qtype: String,
    #[arg(long, default_value_t = 1)]
    count: u64,
    #[arg(long, default_value_t = 1)]
    concurrency: usize,
    #[arg(long)]
    qps: Option<f64>,
    #[arg(long = "timeout-ms", default_value_t = 2000)]
    timeout_ms: u64,
    #[arg(long = "edns-payload-hex")]
    edns_payload_hex: Option<String>,
    #[arg(long = "edns-code", value_name = "CODE")]
    edns_code: Option<u16>,
}

#[derive(Args)]
struct LoadArgs {
    /// Server address; pod IP:port the socket actually opens.
    server: String,
    #[arg(long, value_name = "udp|tcp|dot", default_value = "udp")]
    protocol: String,
    #[arg(long, default_value_t = 53)]
    port: u16,
    /// Path to a newline-delimited query-name corpus; falls back to --name.
    #[arg(long)]
    corpus: Option<PathBuf>,
    #[arg(long, default_value = "example.com")]
    name: String,
    #[arg(long = "type", default_value = "A")]
    qtype: String,
    /// Connections (-c): each owns one socket and its own in-flight window.
    #[arg(short = 'c', long, default_value_t = 32)]
    concurrency: usize,
    /// In-flight queries per connection (-q): total in-flight = c * q.
    #[arg(short = 'q', long = "in-flight", default_value_t = 64)]
    in_flight: usize,
    /// Run duration in seconds (-l); mutually exclusive with --count.
    #[arg(short = 'l', long)]
    duration_s: Option<f64>,
    #[arg(long)]
    count: Option<u64>,
    /// Process-wide query rate cap; unset means as fast as possible.
    #[arg(long)]
    qps: Option<f64>,
    #[arg(long = "timeout-ms", default_value_t = 2000)]
    timeout_ms: u64,
    #[arg(long)]
    randomize: bool,
    #[arg(long, default_value_t = 0)]
    seed: u64,
    /// Auth token: EDNS 65184 on Do53/DoT (URL query on DoH, later).
    #[arg(long)]
    token: Option<String>,
    /// TLS SNI for DoT; defaults to the server IP when unset.
    #[arg(long)]
    sni: Option<String>,
    /// Proceed when the TLS peer negotiates no ALPN (assume the protocol).
    #[arg(long = "alpn-relaxed")]
    alpn_relaxed: bool,
    /// Skip TLS certificate verification (self-signed test targets only).
    #[arg(long)]
    insecure: bool,
}

#[derive(Args)]
struct RequestArgs {
    action: String,
    id: Option<String>,
    #[arg(long)]
    json: Option<String>,
}

#[derive(Args)]
struct RunArgs {
    target: String,
    #[arg(long, default_value_t = 1)]
    parallel: usize,
    #[arg(long = "fail-fast")]
    fail_fast: bool,
    #[arg(long = "dry-run")]
    dry_run: bool,
    #[arg(long)]
    verbose: bool,
    #[arg(long)]
    report: Option<PathBuf>,
}

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
    let argv = std::iter::once("wiresurge".to_string()).chain(args.iter().cloned());
    match Cli::try_parse_from(argv) {
        Ok(cli) => {
            let output_json = cli.output.as_deref() == Some("json");
            match run(cli, cwd) {
                Ok((stdout, code)) => CliOutcome::ok_with_code(stdout, code),
                Err(error) => CliOutcome::err(error, output_json),
            }
        }
        Err(error) => clap_error_to_outcome(error, raw_wants_json(args)),
    }
}

fn run(cli: Cli, cwd: PathBuf) -> Result<(String, i32)> {
    let output_json = cli.output.as_deref() == Some("json");
    let store = WorkspaceStore::new(cwd);
    let output = match cli.command {
        Command::Schema { resource } => schema_for(&resource)?,
        Command::Dns(args) => return dns_command(args, output_json),
        Command::Load(args) => return load_command(args, output_json),
        Command::Workspace { action } => workspace_command(&store, action.as_deref(), output_json)?,
        Command::Request(args) => request_command(&store, args)?,
        Command::Run(args) => run_command(&store, args)?,
        Command::Runner { action } => runner_command(&store, action.as_deref())?,
        Command::Report { action, id } => report_command(&store, action.as_deref(), id.as_deref())?,
        Command::Secret { .. } => secret_command()?,
        Command::Plugin { action } => plugin_command(action.as_deref())?,
    };
    Ok((output, 0))
}

fn raw_wants_json(args: &[String]) -> bool {
    args.iter().any(|arg| arg == "--output=json")
        || args
            .windows(2)
            .any(|window| window[0] == "--output" && window[1] == "json")
}

fn clap_error_to_outcome(error: clap::Error, output_json: bool) -> CliOutcome {
    match error.kind() {
        ErrorKind::DisplayHelp
        | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
        | ErrorKind::DisplayVersion => CliOutcome::ok_with_code(error.render().to_string(), 0),
        _ => CliOutcome::err(clap_error_to_wiresurge(&error), output_json),
    }
}

fn clap_error_to_wiresurge(error: &clap::Error) -> WireSurgeError {
    let code = match error.kind() {
        ErrorKind::UnknownArgument => "unknown_argument",
        ErrorKind::MissingRequiredArgument | ErrorKind::MissingSubcommand => "missing_argument",
        ErrorKind::ArgumentConflict => "conflicting_arguments",
        ErrorKind::InvalidSubcommand => "unknown_command",
        _ => "invalid_argument",
    };
    let rendered = error.render().to_string();
    let message = rendered
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("invalid arguments")
        .trim_start_matches("error: ")
        .to_string();
    let mut wiresurge_error =
        WireSurgeError::new(code, message).with_hint("Run `wiresurge --help`.");
    if let Some(ContextValue::String(arg)) = error.get(ContextKind::InvalidArg) {
        wiresurge_error = wiresurge_error.at(arg.trim_start_matches('-').to_string());
    }
    wiresurge_error
}

fn dns_command(args: DnsArgs, output_json: bool) -> Result<(String, i32)> {
    let transport = DnsTransport::from_str(&args.protocol)?;
    let edns_option = match &args.edns_payload_hex {
        Some(hex) => Some(EdnsOption {
            code: args.edns_code.unwrap_or(DEFAULT_EDNS_CODE),
            payload: decode_hex_payload(hex)?,
        }),
        None => None,
    };
    let config = DnsRunConfig {
        server: args.server,
        port: args.port,
        transport,
        qname: args.name,
        qtype: parse_qtype(&args.qtype)?,
        count: args.count,
        concurrency: args.concurrency,
        timeout: Duration::from_millis(args.timeout_ms),
        qps: args.qps,
        edns_option,
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

fn resolve_addr(server: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = server.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    (server, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .ok_or_else(|| {
            WireSurgeError::new("invalid_server", format!("could not resolve {server}"))
                .at("server")
        })
}

fn build_load_config(args: &LoadArgs) -> Result<LoadConfig> {
    let addr = resolve_addr(&args.server, args.port)?;
    let proto = match args.protocol.to_ascii_lowercase().as_str() {
        "udp" => LoadProto::Do53Udp,
        "tcp" => LoadProto::Do53Tcp,
        "dot" => LoadProto::Dot,
        other => {
            return Err(WireSurgeError::new(
                "invalid_dns_transport",
                format!("protocol must be udp, tcp, or dot, got {other}"),
            )
            .at("protocol"));
        }
    };
    let is_dot = proto == LoadProto::Dot;
    if !is_dot && (args.insecure || args.sni.is_some() || args.alpn_relaxed) {
        return Err(WireSurgeError::new(
            "tls_flag_without_tls",
            "--sni, --alpn-relaxed, and --insecure apply only to --protocol dot",
        )
        .at("protocol"));
    }
    if args.duration_s.is_some() && args.count.is_some() {
        return Err(WireSurgeError::new(
            "conflicting_stop_conditions",
            "set either --duration-s (-l) or --count, not both",
        )
        .at("duration-s"));
    }
    if args.token.is_some() && !is_dot {
        return Err(WireSurgeError::new(
            "token_requires_encrypted_transport",
            "--token rides in EDNS 65184 and is only sent over the encrypted dot transport; plain udp/tcp would expose the credential in cleartext",
        )
        .at("token"));
    }
    let target = if is_dot {
        let config = build_client_config(&TlsParams {
            proto: AppProto::Dot,
            insecure: args.insecure,
        })?;
        ConnectTarget::new(addr).with_tls(
            config,
            AppProto::Dot,
            args.sni.clone(),
            args.alpn_relaxed,
        )
    } else {
        ConnectTarget::new(addr)
    };
    let corpus = match &args.corpus {
        Some(path) => Corpus::load(path)?,
        None => Corpus::single(&args.name),
    };
    let config = LoadConfig {
        proto,
        target,
        corpus,
        qtype: parse_qtype(&args.qtype)?,
        concurrency: args.concurrency,
        in_flight: args.in_flight,
        timeout: Duration::from_millis(args.timeout_ms),
        qps_cap: args.qps,
        duration: args.duration_s.map(Duration::from_secs_f64),
        count: args.count,
        randomize: args.randomize,
        seed: args.seed,
        token: args.token.clone(),
    };
    config.validate()?;
    Ok(config)
}

fn load_command(args: LoadArgs, output_json: bool) -> Result<(String, i32)> {
    let config = build_load_config(&args)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(std::thread::available_parallelism().map_or(8, |n| n.get().min(48)))
        .enable_io()
        .enable_time()
        .thread_name("wiresurge-io")
        .build()
        .map_err(|error| WireSurgeError::new("runtime_init_failed", error.to_string()))?;

    let cancel = CancellationToken::new();
    let (stats, signalled) = runtime.block_on(async {
        let signal_cancel = cancel.clone();
        let signal_task = tokio::spawn(async move {
            wait_for_shutdown().await;
            signal_cancel.cancel();
        });
        let stats = run_load(config, cancel.clone()).await;
        // The run may have ended naturally; stop the listener and capture whether
        // a signal fired (even if it raced in after the actors drained).
        signal_task.abort();
        let signalled = cancel.is_cancelled();
        (stats, signalled)
    });
    let mut stats = stats?;
    stats.cancelled |= signalled;

    let exit_code = if stats.cancelled { 130 } else { 0 };
    let output = if output_json {
        stats.to_json()
    } else {
        format_load_text(&stats)
    };
    Ok((output, exit_code))
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut interrupt = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return,
        };
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn format_load_text(stats: &LoadStats) -> String {
    let recorder = &stats.recorder;
    format!(
        "duration {:.2}s  sent {}  received {}  recv_qps {:.0}\n\
         timeouts {}  errors {}  conn_errors {}  truncated {}\n\
         latency_ms  p50 {:.2}  p95 {:.2}  p99 {:.2}  max {:.2}{}",
        stats.duration_s,
        recorder.sent,
        recorder.received,
        stats.recv_qps(),
        recorder.timeouts,
        recorder.errors,
        recorder.conn_errors,
        recorder.truncated,
        recorder.percentile_ms(0.50),
        recorder.percentile_ms(0.95),
        recorder.percentile_ms(0.99),
        recorder.max_ms(),
        if stats.cancelled {
            "\ncancelled by signal"
        } else {
            ""
        },
    )
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

fn workspace_command(
    store: &WorkspaceStore,
    action: Option<&str>,
    output_json: bool,
) -> Result<String> {
    match action.unwrap_or("show") {
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

fn request_command(store: &WorkspaceStore, args: RequestArgs) -> Result<String> {
    match args.action.as_str() {
        "create" => {
            let input = args.json.ok_or_else(|| {
                WireSurgeError::new("missing_json", "request create requires --json '{...}'")
                    .with_hint("Run `wiresurge schema request` to inspect the accepted shape.")
            })?;
            let request = RequestSpec::from_json(&input)?;
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
            let id = args.id.ok_or_else(|| {
                WireSurgeError::new("missing_argument", "request show requires an id")
            })?;
            Ok(store.load_request(&id)?.to_json())
        }
        "update" => {
            let id = args.id.ok_or_else(|| {
                WireSurgeError::new("missing_argument", "request update requires an id")
            })?;
            let input = args.json.ok_or_else(|| {
                WireSurgeError::new("missing_json", "request update requires --json '{...}'")
                    .with_hint("Run `wiresurge schema request` to inspect the accepted shape.")
            })?;
            let request = RequestSpec::from_json(&input)?;
            store.update_request(&id, &request)?;
            Ok(json_object(&[(
                "request",
                store.load_request(&id)?.to_json(),
            )]))
        }
        "delete" => {
            let id = args.id.ok_or_else(|| {
                WireSurgeError::new("missing_argument", "request delete requires an id")
            })?;
            store.delete_request(&id)?;
            Ok(json_object(&[("deleted", json_string(&id))]))
        }
        _ => Err(WireSurgeError::new(
            "unknown_request_action",
            "request action must be create, list, show, update, or delete",
        )),
    }
}

fn run_command(store: &WorkspaceStore, args: RunArgs) -> Result<String> {
    let options = RunOptions {
        parallel: args.parallel,
        fail_fast: args.fail_fast,
        dry_run: args.dry_run,
        verbose: args.verbose,
        report_dir: args.report,
    };
    if PathBuf::from(&args.target).exists() {
        let input = fs::read_to_string(&args.target)?;
        let request = RequestSpec::from_yaml(&input)?;
        Ok(run_request(store, request, options)?.to_json())
    } else {
        Ok(run_stored_request(store, &args.target, options)?.to_json())
    }
}

fn runner_command(store: &WorkspaceStore, action: Option<&str>) -> Result<String> {
    match action.unwrap_or("list") {
        "list" | "stats" => store.runner_entries_json(),
        _ => Err(WireSurgeError::new(
            "unknown_runner_action",
            "runner action must be list or stats",
        )),
    }
}

fn report_command(
    store: &WorkspaceStore,
    action: Option<&str>,
    id: Option<&str>,
) -> Result<String> {
    match action.unwrap_or("list") {
        "list" => store.report_entries_json(),
        "show" => {
            let id = id.ok_or_else(|| {
                WireSurgeError::new("missing_argument", "report show requires an id")
            })?;
            store.load_report_summary(id)
        }
        "export" => Err(WireSurgeError::new(
            "not_implemented",
            "report export is reserved for the report phase",
        )
        .with_hint(
            "Current runs already write summary.json, details.json, and index.html when --report is used.",
        )),
        _ => Err(WireSurgeError::new(
            "unknown_report_action",
            "report action must be list, show, or export",
        )),
    }
}

fn secret_command() -> Result<String> {
    Err(
        WireSurgeError::new("not_implemented", "keychain-backed secrets are planned for phase 7")
            .with_hint(
                "Do not store real secrets in request files; use placeholder values until the keychain adapter lands.",
            ),
    )
}

fn plugin_command(action: Option<&str>) -> Result<String> {
    match action.unwrap_or("manifest-example") {
        "manifest-example" => Ok(PluginManifestDraft::example().to_json()),
        _ => Err(WireSurgeError::new(
            "unknown_plugin_action",
            "plugin action must be manifest-example",
        )),
    }
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
    fn dns_accepts_equals_form_for_output_flag() {
        let outcome = dispatch(
            &[
                "dns".to_string(),
                "127.0.0.1".to_string(),
                "--protocol=invalid".to_string(),
                "--output=json".to_string(),
            ],
            temp_dir(),
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome.stdout.contains("invalid_dns_transport"));
    }

    #[test]
    fn unknown_flag_is_rejected_not_ignored() {
        let outcome = dispatch(
            &[
                "dns".to_string(),
                "127.0.0.1".to_string(),
                "--nope".to_string(),
                "--output".to_string(),
                "json".to_string(),
            ],
            temp_dir(),
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome.stdout.contains("unknown_argument"));
    }

    #[test]
    fn load_rejects_token_on_cleartext_transport() {
        let outcome = dispatch(
            &[
                "load".into(),
                "127.0.0.1".into(),
                "--protocol".into(),
                "udp".into(),
                "--count".into(),
                "1".into(),
                "--token".into(),
                "secret".into(),
                "--output".into(),
                "json".into(),
            ],
            temp_dir(),
        );
        assert_eq!(outcome.code, 1);
        assert!(
            outcome
                .stdout
                .contains("token_requires_encrypted_transport")
        );
    }

    #[test]
    fn load_rejects_tls_flags_on_plain_transport() {
        let outcome = dispatch(
            &[
                "load".into(),
                "127.0.0.1".into(),
                "--protocol".into(),
                "tcp".into(),
                "--count".into(),
                "1".into(),
                "--insecure".into(),
                "--output".into(),
                "json".into(),
            ],
            temp_dir(),
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome.stdout.contains("tls_flag_without_tls"));
    }

    #[test]
    fn load_rejects_both_duration_and_count() {
        let outcome = dispatch(
            &[
                "load".into(),
                "127.0.0.1".into(),
                "--count".into(),
                "1".into(),
                "--duration-s".into(),
                "1".into(),
                "--output".into(),
                "json".into(),
            ],
            temp_dir(),
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome.stdout.contains("conflicting_stop_conditions"));
    }

    #[test]
    fn load_protocol_is_case_insensitive() {
        let outcome = dispatch(
            &[
                "load".into(),
                "127.0.0.1".into(),
                "--protocol".into(),
                "UDP".into(),
                "--count".into(),
                "0".into(),
                "--output".into(),
                "json".into(),
            ],
            temp_dir(),
        );
        // count 0 means no work; the run completes immediately. The point is the
        // uppercase protocol is accepted rather than rejected as invalid.
        assert_eq!(outcome.code, 0, "{}", outcome.stdout);
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
