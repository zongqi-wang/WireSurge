use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

use std::net::{SocketAddr, ToSocketAddrs};

use clap::error::{ContextKind, ContextValue, ErrorKind};
use clap::{Args, Parser, Subcommand};
use comfy_table::{Cell, ContentArrangement, Table, presets::UTF8_FULL};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use url::{Position, Url};
use wiresurge_core::{RequestSpec, Result, WireSurgeError, schema_for, serialize_json};
use wiresurge_corpus::Corpus;
use wiresurge_dns::parse_qtype;
use wiresurge_engine::load::{
    LoadConfig, LoadProto, LoadStats, ProgressConfig, run_load, run_load_with_progress,
};
use wiresurge_engine::{
    RunOptions, run_request_with_cancellation, run_stored_request_with_cancellation,
};
use wiresurge_metrics::RunSnapshot;
use wiresurge_plugins::PluginManifestDraft;
use wiresurge_storage::WorkspaceStore;
use wiresurge_transport::{
    AppProto, ConnectTarget, HttpMethod, HttpTemplate, ProxyHeader, TlsParams, build_client_config,
};

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
// The Load variant carries many flags and dwarfs the others, but a clap
// Subcommand field must impl Args, which Box<LoadArgs> does not — and the enum
// is parsed once at startup, so the size gap is irrelevant.
#[allow(clippy::large_enum_variant)]
enum Command {
    Schema {
        resource: String,
    },
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
struct LoadArgs {
    /// Server address; pod IP:port the socket actually opens.
    server: String,
    #[arg(long, value_name = "udp|tcp|dot|doh", default_value = "udp")]
    protocol: String,
    #[arg(long, default_value_t = 53)]
    port: u16,
    /// DoH endpoint URL (required for --protocol doh), e.g.
    /// https://resolver.example/dns-query. The socket still opens to <server>;
    /// the URL host becomes the default SNI and the HTTP :authority.
    #[arg(long)]
    url: Option<String>,
    /// DoH HTTP method: post (raw wire body, default) or get (base64url ?dns=).
    #[arg(long = "doh-method", value_name = "get|post")]
    doh_method: Option<String>,
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
    /// Auth token: EDNS 65184 on DoT, `?token=` URL query on DoH.
    #[arg(long)]
    token: Option<String>,
    /// PROXY protocol v2 source (mocked customer) as IP:PORT, e.g.
    /// 192.0.2.10:50000. Requires --proxy-dst; TCP-based transports only.
    #[arg(long = "proxy-src", value_name = "IP:PORT")]
    proxy_src: Option<String>,
    /// PROXY protocol v2 destination (NLB VIP) as IP:PORT. Requires --proxy-src.
    #[arg(long = "proxy-dst", value_name = "IP:PORT")]
    proxy_dst: Option<String>,
    /// TLS SNI for DoT/DoH; defaults to the DoH URL host, else the server IP.
    #[arg(long)]
    sni: Option<String>,
    /// Proceed when the TLS peer negotiates no ALPN (assume the protocol).
    #[arg(long = "alpn-relaxed")]
    alpn_relaxed: bool,
    /// Skip TLS certificate verification (self-signed test targets only).
    #[arg(long)]
    insecure: bool,
    /// Suppress the live progress line even on a TTY (banner and final summary
    /// still print). Progress is always off under --output json or non-TTY.
    #[arg(long = "no-progress")]
    no_progress: bool,
    /// Live progress refresh interval in milliseconds.
    #[arg(long = "progress-interval", value_name = "MS", default_value_t = 1000)]
    progress_interval_ms: u64,
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
                stdout: serde_json::to_string(&serde_json::json!({ "error": error }))
                    .unwrap_or_else(|_| error.to_json()),
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
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    return CliOutcome::err(
                        WireSurgeError::new("runtime_initialization_failed", error.to_string()),
                        output_json,
                    );
                }
            };
            match runtime.block_on(run(cli, cwd)) {
                Ok((stdout, code)) => CliOutcome::ok_with_code(stdout, code),
                Err(error) => CliOutcome::err(error, output_json),
            }
        }
        Err(error) => clap_error_to_outcome(error, raw_wants_json(args)),
    }
}

async fn run(cli: Cli, cwd: PathBuf) -> Result<(String, i32)> {
    let output_json = cli.output.as_deref() == Some("json");
    let store = WorkspaceStore::new(cwd);
    let output = match cli.command {
        Command::Schema { resource } => schema_for(&resource)?,
        Command::Load(args) => return load_command(args, output_json).await,
        Command::Workspace { action } => workspace_command(&store, action.as_deref(), output_json)?,
        Command::Request(args) => request_command(&store, args)?,
        Command::Run(args) => return run_command(&store, args, output_json).await,
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
        "doh" => LoadProto::Doh,
        other => {
            return Err(WireSurgeError::new(
                "invalid_dns_transport",
                format!("protocol must be udp, tcp, dot, or doh, got {other}"),
            )
            .at("protocol"));
        }
    };
    let is_dot = proto == LoadProto::Dot;
    let is_doh = proto == LoadProto::Doh;
    let is_tls = is_dot || is_doh;
    if !is_tls && (args.insecure || args.sni.is_some() || args.alpn_relaxed) {
        return Err(WireSurgeError::new(
            "tls_flag_without_tls",
            "--sni, --alpn-relaxed, and --insecure apply only to --protocol dot or doh",
        )
        .at("protocol"));
    }
    if args.url.is_some() && !is_doh {
        return Err(WireSurgeError::new(
            "url_requires_doh",
            "--url is only used by --protocol doh",
        )
        .at("url"));
    }
    if args.doh_method.is_some() && !is_doh {
        return Err(WireSurgeError::new(
            "doh_method_requires_doh",
            "--doh-method is only used by --protocol doh",
        )
        .at("doh-method"));
    }
    if args.duration_s.is_some() && args.count.is_some() {
        return Err(WireSurgeError::new(
            "conflicting_stop_conditions",
            "set either --duration-s (-l) or --count, not both",
        )
        .at("duration-s"));
    }
    if args.token.is_some() && !is_tls {
        return Err(WireSurgeError::new(
            "token_requires_encrypted_transport",
            "--token is a credential and is only sent over the encrypted dot or doh transports; plain udp/tcp would expose it in cleartext",
        )
        .at("token"));
    }
    if args.token.is_some() && args.insecure {
        // --insecure installs a no-op certificate verifier, so the peer identity
        // is unauthenticated; sending the credential then exposes it to any MITM
        // that can terminate the TLS handshake. Refuse the combination.
        return Err(WireSurgeError::new(
            "token_requires_verified_peer",
            "--token must not be combined with --insecure: an unverified peer could capture the credential; drop --insecure or omit the token",
        )
        .at("token"));
    }
    let proxy = build_proxy_header(args)?;
    let mut target = if is_dot {
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
    } else if is_doh {
        build_doh_target(args, addr)?
    } else {
        ConnectTarget::new(addr)
    };
    if let Some(proxy) = proxy {
        target = target.with_proxy(proxy);
    }
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

/// Build a DoH connect target from the load args. The socket opens to `addr`
/// (the pod), while the `--url` host supplies the TLS SNI and the HTTP
/// `:authority`; the auth token is folded into the request query so it rides
/// the URL rather than an EDNS option.
fn build_doh_target(args: &LoadArgs, addr: SocketAddr) -> Result<ConnectTarget> {
    let raw = args.url.as_deref().ok_or_else(|| {
        WireSurgeError::new(
            "doh_url_required",
            "--protocol doh requires --url, e.g. https://resolver.example/dns-query",
        )
        .at("url")
    })?;
    let url = Url::parse(raw)
        .map_err(|error| WireSurgeError::new("invalid_url", error.to_string()).at("url"))?;
    if url.scheme() != "https" {
        return Err(WireSurgeError::new("invalid_url", "DoH URL must use https").at("url"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        // Userinfo would ride into the HTTP/2 :authority pseudo-header, which
        // RFC 9113 §8.3.1 forbids; a conformant peer rejects the request and the
        // embedded credential leaks. Reject up front rather than fail every query.
        return Err(WireSurgeError::new(
            "invalid_url",
            "DoH URL must not embed userinfo (user:pass@); pass credentials via --token",
        )
        .at("url"));
    }
    let host = url.host().ok_or_else(|| {
        WireSurgeError::new("invalid_url", "DoH URL must include a host").at("url")
    })?;
    // SNI must be the bare host: rustls rejects an IPv6 literal in its bracketed
    // URL form (`[::1]`), so use the unbracketed address for that case.
    let sni_host = match host {
        url::Host::Ipv6(addr) => addr.to_string(),
        other => other.to_string(),
    };

    let method = match args
        .doh_method
        .as_deref()
        .unwrap_or("post")
        .to_ascii_lowercase()
        .as_str()
    {
        "post" => HttpMethod::Post,
        "get" => HttpMethod::Get,
        other => {
            return Err(WireSurgeError::new(
                "invalid_doh_method",
                format!("--doh-method must be get or post, got {other}"),
            )
            .at("doh-method"));
        }
    };

    // Scheme + authority + path, no query/fragment: the per-query suffix
    // (?dns=, ?token=) is appended by the adapter from `query` below.
    let base_uri = url[..Position::AfterPath].to_string();
    // Preserve any query already on the URL, then fold the token in with proper
    // percent-encoding via the url crate rather than hand-splicing.
    let mut query_url = url.clone();
    if let Some(token) = &args.token {
        query_url.query_pairs_mut().append_pair("token", token);
    }
    let query = query_url.query().unwrap_or("").to_string();

    let sni = args.sni.clone().or(Some(sni_host));
    let config = build_client_config(&TlsParams {
        proto: AppProto::Doh,
        insecure: args.insecure,
    })?;
    Ok(ConnectTarget::new(addr)
        .with_tls(config, AppProto::Doh, sni, args.alpn_relaxed)
        .with_http(HttpTemplate {
            method,
            base_uri,
            query,
        }))
}

/// Parse the optional PROXY v2 source/destination pair. Both endpoints are
/// required together. The header carries a mocked customer source and the
/// resolver's NLB VIP destination, independent of the socket peer the run
/// actually opens to. It rides every protocol: a stream connection
/// (TCP/DoT/DoH) writes it as the connection preamble, a UDP transport prepends
/// it to each datagram.
fn build_proxy_header(args: &LoadArgs) -> Result<Option<ProxyHeader>> {
    let (src, dst) = match (&args.proxy_src, &args.proxy_dst) {
        (None, None) => return Ok(None),
        (Some(src), Some(dst)) => (src, dst),
        _ => {
            return Err(WireSurgeError::new(
                "proxy_requires_both_endpoints",
                "--proxy-src and --proxy-dst must be set together",
            )
            .at("proxy"));
        }
    };
    let src = parse_proxy_addr(src, "proxy-src")?;
    let dst = parse_proxy_addr(dst, "proxy-dst")?;
    // The wire format carries one family byte for the pair, so a v4/v6 mix can
    // never be encoded. Reject it here — alongside the other proxy gates — rather
    // than letting it surface as an opaque per-connection error mid-run.
    if src.is_ipv4() != dst.is_ipv4() {
        return Err(WireSurgeError::new(
            "proxy_family_mismatch",
            "--proxy-src and --proxy-dst must be the same IP family (both IPv4 or both IPv6)",
        )
        .at("proxy"));
    }
    Ok(Some(ProxyHeader::new(src, dst)))
}

/// Parse a PROXY endpoint and canonicalize an IPv4-mapped IPv6 literal
/// (`[::ffff:a.b.c.d]`) back to its IPv4 form, so the operator gets the TCPv4
/// header they meant rather than a surprising 36-byte TCPv6 one.
fn parse_proxy_addr(value: &str, field: &str) -> Result<SocketAddr> {
    let addr = value.parse::<SocketAddr>().map_err(|error| {
        WireSurgeError::new(
            format!("invalid_{}", field.replace('-', "_")),
            error.to_string(),
        )
        .at(field)
    })?;
    Ok(SocketAddr::new(addr.ip().to_canonical(), addr.port()))
}

async fn load_command(args: LoadArgs, output_json: bool) -> Result<(String, i32)> {
    let config = build_load_config(&args)?;

    let progress_enabled = !output_json && !args.no_progress && std::io::stderr().is_terminal();
    if !output_json {
        eprintln!("{}", format_load_banner(&args, &config));
    }

    let cancellation = CancellationToken::new();
    let (mut stats, exit_code) = if progress_enabled {
        // Floored: each tick clones every actor's histogram, so a sub-50ms
        // cadence at high -c would perturb the throughput being measured.
        let interval = Duration::from_millis(args.progress_interval_ms.max(50));
        let (tx, rx) = watch::channel(RunSnapshot::default());
        let renderer = tokio::spawn(render_progress(rx));
        let execution = run_load_with_progress(
            config,
            cancellation.clone(),
            Some((ProgressConfig { interval }, tx)),
        );
        let result = drive_with_signal(execution, &cancellation).await;
        renderer.abort();
        let _ = renderer.await;
        result?
    } else {
        let execution = run_load(config, cancellation.clone());
        drive_with_signal(execution, &cancellation).await?
    };

    stats.cancelled |= exit_code != 0;
    let output = if output_json {
        stats.to_json()?
    } else {
        format_load_text(&stats)
    };
    Ok((output, exit_code))
}

async fn drive_with_signal<F>(
    execution: F,
    cancellation: &CancellationToken,
) -> Result<(LoadStats, i32)>
where
    F: std::future::Future<Output = Result<LoadStats>>,
{
    tokio::pin!(execution);
    let signal = shutdown_signal();
    tokio::pin!(signal);
    tokio::select! {
        result = &mut execution => Ok((result?, 0)),
        signal_code = &mut signal => {
            let signal_code = signal_code?;
            cancellation.cancel();
            Ok((execution.await?, signal_code))
        }
    }
}

fn format_load_banner(args: &LoadArgs, config: &LoadConfig) -> String {
    let query = match &args.corpus {
        Some(path) => format!("names from corpus {}", path.display()),
        None => format!("{} {} queries", args.name, args.qtype.to_uppercase()),
    };
    let stop = match (args.duration_s, args.count) {
        (Some(secs), _) => format!("for {secs} seconds"),
        (_, Some(count)) => format!("until {} queries are sent", group_u64(count)),
        _ => "until interrupted".to_string(),
    };
    let total_in_flight = config.concurrency * config.in_flight;
    let rate = match args.qps {
        Some(qps) => format!("capped at {} queries/sec", group_u64(qps as u64)),
        None => "as fast as the target allows".to_string(),
    };

    let mut lines = vec![
        format!(
            "Load test: sending {query} to {} over {}.",
            config.target.tcp_addr,
            args.protocol.to_uppercase(),
        ),
        format!(
            "Using {} connections (-c), each keeping {} queries in flight (-q) = {} concurrent queries total ({rate}).",
            config.concurrency, config.in_flight, total_in_flight,
        ),
        format!(
            "Running {stop}. PROXY header: {}. Auth token: {}.",
            if config.target.proxy.is_some() {
                "on"
            } else {
                "off"
            },
            if config.token.is_some() {
                "set"
            } else {
                "none"
            },
        ),
    ];
    lines.push(String::new());
    lines.push(
        "── Live progress ─────────────────────────────────────────────────────────────"
            .to_string(),
    );
    lines.push(
        "Each line is one sample. Counts are cumulative; rates are instantaneous.".to_string(),
    );
    lines.push(progress_header());
    lines.join("\n")
}

/// Column titles for the live progress rows, aligned to `format_progress_row`.
fn progress_header() -> String {
    format!(
        "{:>6}  {:>11}  {:>11}  {:>9}  {:>9}  {:>6}  {:>7}  {:>7}  {:>6}  {:>6}   {}",
        "time",
        "sent",
        "received",
        "recv/s",
        "noerror/s",
        "infl",
        "p50 ms",
        "p99 ms",
        "tmout",
        "error",
        "rcodes",
    )
}

fn format_progress_row(snap: &RunSnapshot, recv_qps: f64, noerror_qps: f64) -> String {
    format!(
        "{:>5.1}s  {:>11}  {:>11}  {:>9.0}  {:>9.0}  {:>6}  {:>7.1}  {:>7.1}  {:>6}  {:>6}   {}",
        snap.elapsed_s,
        group_u64(snap.aggregate.sent),
        group_u64(snap.aggregate.received),
        recv_qps,
        noerror_qps,
        snap.aggregate.in_flight,
        snap.aggregate.p50_ms,
        snap.aggregate.p99_ms,
        snap.aggregate.timeouts,
        snap.aggregate.errors + snap.aggregate.conn_errors,
        format_rcodes_inline(&snap.aggregate.rcodes),
    )
}

/// Compact `NAME=count` rcode list for one progress line (`-` when empty).
fn format_rcodes_inline(rcodes: &std::collections::BTreeMap<String, u64>) -> String {
    if rcodes.is_empty() {
        return "-".to_string();
    }
    rcodes
        .iter()
        .map(|(name, count)| format!("{name}={count}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Thousands-grouped decimal (e.g. 1234567 -> "1,234,567").
fn group_u64(value: u64) -> String {
    let digits = value.to_string();
    let bytes = digits.as_bytes();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, &b) in bytes.iter().enumerate() {
        if i != 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(b as char);
    }
    out
}

async fn render_progress(mut rx: watch::Receiver<RunSnapshot>) {
    let mut prev: Option<RunSnapshot> = None;
    while rx.changed().await.is_ok() {
        let snap = rx.borrow().clone();
        // Final frame is shown as the summary table; the t=0 seed has nothing.
        if snap.final_sample || snap.elapsed_s == 0.0 {
            continue;
        }
        // First frame has no prior; fall back to the cumulative rate.
        let (recv_qps, noerror_qps) = match &prev {
            Some(p) if snap.elapsed_s > p.elapsed_s => {
                let dt = snap.elapsed_s - p.elapsed_s;
                let delta = |now: u64, was: u64| now.saturating_sub(was) as f64 / dt;
                (
                    delta(snap.aggregate.received, p.aggregate.received),
                    delta(snap.aggregate.noerror, p.aggregate.noerror),
                )
            }
            _ => (snap.aggregate.recv_qps, snap.aggregate.noerror_qps),
        };
        // One persistent line per tick: a scrolling log, not an in-place redraw.
        eprintln!("{}", format_progress_row(&snap, recv_qps, noerror_qps));
        prev = Some(snap);
    }
}

fn format_load_text(stats: &LoadStats) -> String {
    let recorder = &stats.recorder;
    let sent = recorder.sent;
    let received = recorder.received;
    let noerror = recorder.noerror();
    let response_pct = |count: u64| {
        if sent > 0 {
            100.0 * count as f64 / sent as f64
        } else {
            0.0
        }
    };

    let rcodes = recorder.rcode_breakdown();
    let rcode_lines = if rcodes.is_empty() {
        "    (no responses)".to_string()
    } else {
        rcodes
            .iter()
            .map(|(name, count)| {
                format!(
                    "    {name:<10} {:>13}  ({:.1}% of sent)",
                    group_u64(*count),
                    response_pct(*count)
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let mut summary = format!(
        "── Summary (totals over the whole run) ───────────────────────────────────────\n\
         duration         {:>10.2}  seconds\n\
         sent             {:>10}  queries\n\
         received         {:>10}  responses  ({:.1}% of sent)\n\
         noerror          {:>10}  responses  ({:.1}% of sent)\n\
         throughput       {:>10}  responses/sec (received)\n\
         goodput          {:>10}  responses/sec (noerror)\n\
         timeouts         {:>10}  queries\n\
         transport errors {:>10}  queries\n\
         conn errors      {:>10}  connections\n\
         truncated        {:>10}  responses\n\
         latency          p50 {:.2} ms   p95 {:.2} ms   p99 {:.2} ms   max {:.2} ms\n\
         rcodes:\n{}",
        stats.duration_s,
        group_u64(sent),
        group_u64(received),
        response_pct(received),
        group_u64(noerror),
        response_pct(noerror),
        group_u64(stats.recv_qps() as u64),
        group_u64(stats.noerror_qps() as u64),
        group_u64(recorder.timeouts),
        group_u64(recorder.errors),
        group_u64(recorder.conn_errors),
        group_u64(recorder.truncated),
        recorder.percentile_ms(0.50),
        recorder.percentile_ms(0.95),
        recorder.percentile_ms(0.99),
        recorder.max_ms(),
        rcode_lines,
    );
    if stats.cancelled {
        summary.push_str("\ncancelled by signal");
    }
    if stats.workers.is_empty() {
        return summary;
    }
    format!(
        "{summary}\n\n── Per-connection breakdown ──────────────────────────────────────────────────\n{}",
        format_worker_table(&stats.workers)
    )
}

fn format_worker_table(workers: &[wiresurge_metrics::WorkerStats]) -> String {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "connection",
            "sent q/s",
            "recv q/s",
            "p50 ms",
            "p95 ms",
            "p99 ms",
            "err q/s",
            "tmout q/s",
        ]);
    for worker in workers {
        table.add_row(vec![
            Cell::new(&worker.id),
            Cell::new(format!("{:.0}", worker.qps)),
            Cell::new(format!("{:.0}", worker.rps)),
            Cell::new(format!("{:.2}", worker.p50_ms)),
            Cell::new(format!("{:.2}", worker.p95_ms)),
            Cell::new(format!("{:.2}", worker.p99_ms)),
            Cell::new(format!("{:.1}", worker.error_rate)),
            Cell::new(format!("{:.1}", worker.timeout_rate)),
        ]);
    }
    table.to_string()
}

#[cfg(unix)]
async fn shutdown_signal() -> Result<i32> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())
        .map_err(|error| WireSurgeError::new("signal_handler_install_failed", error.to_string()))?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.map_err(|error| WireSurgeError::new("signal_handler_failed", error.to_string()))?;
            Ok(130)
        }
        _ = terminate.recv() => Ok(143),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> Result<i32> {
    tokio::signal::ctrl_c()
        .await
        .map_err(|error| WireSurgeError::new("signal_handler_failed", error.to_string()))?;
    Ok(130)
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
                serialize_json(&serde_json::json!({
                    "workspace": parse_json_output(&workspace)?
                }))
            } else {
                Ok(format!(
                    "Initialized WireSurge workspace at {}",
                    store.root().display()
                ))
            }
        }
        "list" => {
            if store.exists() {
                serialize_json(&vec![parse_json_output(&store.workspace_json()?)?])
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
            serialize_json(&serde_json::json!({ "request": request.to_json_value()? }))
        }
        "list" => {
            let requests = store
                .list_requests()?
                .iter()
                .map(RequestSpec::to_json_value)
                .collect::<Result<Vec<_>>>()?;
            serialize_json(&requests)
        }
        "show" => {
            let id = args.id.ok_or_else(|| {
                WireSurgeError::new("missing_argument", "request show requires an id")
            })?;
            store.load_request(&id)?.to_json()
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
            serialize_json(&serde_json::json!({
                "request": store.load_request(&id)?.to_json_value()?
            }))
        }
        "delete" => {
            let id = args.id.ok_or_else(|| {
                WireSurgeError::new("missing_argument", "request delete requires an id")
            })?;
            store.delete_request(&id)?;
            serialize_json(&serde_json::json!({ "deleted": id }))
        }
        _ => Err(WireSurgeError::new(
            "unknown_request_action",
            "request action must be create, list, show, update, or delete",
        )),
    }
}

async fn run_command(
    store: &WorkspaceStore,
    args: RunArgs,
    output_json: bool,
) -> Result<(String, i32)> {
    let options = RunOptions {
        parallel: args.parallel,
        fail_fast: args.fail_fast,
        dry_run: args.dry_run,
        verbose: args.verbose,
        report_dir: args.report,
    };
    let cancellation = CancellationToken::new();
    let execution_cancellation = cancellation.clone();
    let execution = async {
        if PathBuf::from(&args.target).exists() {
            let input = fs::read_to_string(&args.target)?;
            let request = RequestSpec::from_yaml(&input)?;
            run_request_with_cancellation(store, request, options, execution_cancellation).await
        } else {
            run_stored_request_with_cancellation(
                store,
                &args.target,
                options,
                execution_cancellation,
            )
            .await
        }
    };
    tokio::pin!(execution);
    let signal = shutdown_signal();
    tokio::pin!(signal);
    tokio::select! {
        result = &mut execution => Ok((result?.to_json()?, 0)),
        signal_code = &mut signal => {
            let signal_code = signal_code?;
            cancellation.cancel();
            let cancellation_error = match execution.await {
                Err(error) => error,
                Ok(_) => WireSurgeError::new("run_cancelled", "HTTP run was cancelled"),
            };
            let output = if output_json {
                serialize_json(&serde_json::json!({ "error": cancellation_error }))?
            } else {
                cancellation_error.to_string()
            };
            Ok((output, signal_code))
        }
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
        "manifest-example" => PluginManifestDraft::example().to_json(),
        _ => Err(WireSurgeError::new(
            "unknown_plugin_action",
            "plugin action must be manifest-example",
        )),
    }
}

fn parse_json_output(input: &str) -> Result<serde_json::Value> {
    serde_json::from_str(input).map_err(|error| {
        WireSurgeError::new("invalid_internal_json", error.to_string()).at(format!(
            "line {}, column {}",
            error.line(),
            error.column()
        ))
    })
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
    fn load_help_lists_protocols() {
        let outcome = dispatch(&["load".to_string(), "--help".to_string()], temp_dir());
        assert_eq!(outcome.code, 0);
        assert!(outcome.stdout.contains("--protocol <udp|tcp|dot|doh>"));
        assert!(outcome.stdout.contains("--concurrency"));
    }

    #[test]
    fn load_rejects_invalid_protocol_with_structured_error() {
        let outcome = dispatch(
            &[
                "load".to_string(),
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
    fn load_accepts_equals_form_for_output_flag() {
        let outcome = dispatch(
            &[
                "load".to_string(),
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
                "load".to_string(),
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
    fn load_json_output_carries_workers() {
        // --count 0 completes without a server; fd-level stream cleanliness is
        // covered in tests/load_streams.rs.
        let outcome = dispatch(
            &[
                "load".into(),
                "127.0.0.1".into(),
                "--protocol".into(),
                "udp".into(),
                "--count".into(),
                "0".into(),
                "--output".into(),
                "json".into(),
            ],
            temp_dir(),
        );
        assert_eq!(outcome.code, 0);
        let value: serde_json::Value =
            serde_json::from_str(&outcome.stdout).expect("stdout is a single JSON value");
        assert!(
            value.get("workers").is_some(),
            "json carries workers: {}",
            outcome.stdout
        );
        assert!(value.get("noerror_qps").is_some());
        assert!(value["workers"].is_array());
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
    fn load_rejects_token_with_insecure() {
        let outcome = dispatch(
            &[
                "load".into(),
                "127.0.0.1".into(),
                "--protocol".into(),
                "doh".into(),
                "--url".into(),
                "https://r.example/dns-query".into(),
                "--token".into(),
                "secret".into(),
                "--insecure".into(),
                "--count".into(),
                "1".into(),
                "--output".into(),
                "json".into(),
            ],
            temp_dir(),
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome.stdout.contains("token_requires_verified_peer"));
    }

    #[test]
    fn load_rejects_doh_method_on_non_doh() {
        let outcome = dispatch(
            &[
                "load".into(),
                "127.0.0.1".into(),
                "--protocol".into(),
                "udp".into(),
                "--doh-method".into(),
                "get".into(),
                "--count".into(),
                "1".into(),
                "--output".into(),
                "json".into(),
            ],
            temp_dir(),
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome.stdout.contains("doh_method_requires_doh"));
    }

    #[test]
    fn load_rejects_doh_url_with_userinfo() {
        let outcome = dispatch(
            &[
                "load".into(),
                "127.0.0.1".into(),
                "--protocol".into(),
                "doh".into(),
                "--url".into(),
                "https://user:pass@r.example/dns-query".into(),
                "--count".into(),
                "1".into(),
                "--output".into(),
                "json".into(),
            ],
            temp_dir(),
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome.stdout.contains("invalid_url"));
    }

    #[test]
    fn load_rejects_proxy_with_only_one_endpoint() {
        let outcome = dispatch(
            &[
                "load".into(),
                "127.0.0.1".into(),
                "--protocol".into(),
                "tcp".into(),
                "--proxy-src".into(),
                "192.0.2.1:50000".into(),
                "--count".into(),
                "1".into(),
                "--output".into(),
                "json".into(),
            ],
            temp_dir(),
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome.stdout.contains("proxy_requires_both_endpoints"));
    }

    #[test]
    fn load_accepts_proxy_on_udp() {
        let outcome = dispatch(
            &[
                "load".into(),
                "127.0.0.1".into(),
                "--protocol".into(),
                "udp".into(),
                "--proxy-src".into(),
                "192.0.2.1:50000".into(),
                "--proxy-dst".into(),
                "203.0.113.5:53".into(),
                "--count".into(),
                "0".into(),
                "--output".into(),
                "json".into(),
            ],
            temp_dir(),
        );
        assert_eq!(outcome.code, 0, "{}", outcome.stdout);
    }

    #[test]
    fn load_rejects_proxy_family_mismatch() {
        let outcome = dispatch(
            &[
                "load".into(),
                "127.0.0.1".into(),
                "--protocol".into(),
                "tcp".into(),
                "--proxy-src".into(),
                "192.0.2.1:50000".into(),
                "--proxy-dst".into(),
                "[2001:db8::2]:443".into(),
                "--count".into(),
                "1".into(),
                "--output".into(),
                "json".into(),
            ],
            temp_dir(),
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome.stdout.contains("proxy_family_mismatch"));
    }

    #[test]
    fn load_rejects_udp_proxy_with_single_endpoint() {
        let outcome = dispatch(
            &[
                "load".into(),
                "127.0.0.1".into(),
                "--protocol".into(),
                "udp".into(),
                "--proxy-src".into(),
                "192.0.2.1:50000".into(),
                "--count".into(),
                "1".into(),
                "--output".into(),
                "json".into(),
            ],
            temp_dir(),
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome.stdout.contains("proxy_requires_both_endpoints"));
    }

    #[test]
    fn proxy_addr_canonicalizes_ipv4_mapped_v6() {
        // An IPv4-mapped IPv6 literal must collapse to its IPv4 form so the
        // emitted PROXY header is TCPv4 (family 0x11), not a surprising TCPv6.
        let addr = parse_proxy_addr("[::ffff:192.0.2.1]:443", "proxy-src").unwrap();
        assert!(addr.is_ipv4(), "::ffff: literal must canonicalize to IPv4");
        assert_eq!(addr.to_string(), "192.0.2.1:443");
    }

    #[test]
    fn load_accepts_proxy_on_tcp() {
        // count 0 = no work, completes immediately; the point is that valid
        // --proxy-src/--proxy-dst on a TCP transport parse and build without error.
        let outcome = dispatch(
            &[
                "load".into(),
                "127.0.0.1".into(),
                "--protocol".into(),
                "tcp".into(),
                "--proxy-src".into(),
                "192.0.2.1:50000".into(),
                "--proxy-dst".into(),
                "203.0.113.5:443".into(),
                "--count".into(),
                "0".into(),
                "--output".into(),
                "json".into(),
            ],
            temp_dir(),
        );
        assert_eq!(outcome.code, 0, "{}", outcome.stdout);
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
