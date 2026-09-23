#![warn(clippy::pedantic)]
#![forbid(unsafe_code)]

//! The admin control tool for `postfix-ratelimitd`'s optional control socket
//! (see `Config::control_socket`). Deliberately synchronous and its own
//! binary, separate from the daemon: it's a one-shot query, not a server, so
//! it has no need for an async runtime, and giving it its own binary means
//! the daemon's CLI never needs a "run the daemon" verb alongside admin ones.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use postfix_ratelimitd::config::Config;
use postfix_ratelimitd::control;

/// Bounds how long a query waits for a reply, so a stuck or unresponsive
/// daemon can't hang this tool forever.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Parser)]
#[command(version, about = "Admin control tool for postfix-ratelimitd's optional control socket")]
struct Cli {
    /// Path to the daemon's TOML config file, used to find its control socket
    #[arg(short, long, default_value = postfix_ratelimitd::config::DEFAULT_CONFIG_PATH, conflicts_with = "socket")]
    config: PathBuf,

    /// Connect directly to this control socket, bypassing the config file entirely
    #[arg(short, long, env = "POSTFIX_RATELIMITCTL_SOCKET")]
    socket: Option<PathBuf>,

    /// Print the JSON-RPC result as-is instead of formatted output. This is the wire protocol,
    /// not a stable interface - its shape can change between versions.
    #[arg(long)]
    raw_response: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, clap::Subcommand)]
enum Command {
    /// Check that the daemon's control socket is up and responding.
    Ping,
    /// Query an identity's current rate-limit status.
    #[command(subcommand)]
    Limits(LimitsCommand),
}

/// One subcommand per identity kind, mirroring the control protocol's own
/// `limits.<kind>` method naming - each kind gets its own precisely-named
/// argument rather than a generic value reinterpreted by a flag.
#[derive(Debug, Clone, clap::Subcommand)]
enum LimitsCommand {
    /// Query one SASL username's current rate-limit status.
    Sasl {
        /// The SASL username to query.
        username: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

fn run(cli: &Cli) -> Result<(), ExitCode> {
    let control_socket = resolve_control_socket(cli.socket.as_deref(), &cli.config)?;
    match &cli.command {
        Command::Ping => run_ping_command(&control_socket, cli.raw_response),
        Command::Limits(LimitsCommand::Sasl { username }) => {
            run_status_command(&control_socket, username, cli.raw_response)
        }
    }
}

/// `--socket` if given, bypassing the config file entirely; otherwise `config_path`'s configured
/// control socket. Failures go straight to stderr - this tool never sets up logging.
fn resolve_control_socket(socket: Option<&Path>, config_path: &Path) -> Result<PathBuf, ExitCode> {
    if let Some(socket) = socket {
        return Ok(socket.to_path_buf());
    }
    let config = Config::load(config_path).map_err(|err| {
        eprintln!("failed to load config {}: {err}", config_path.display());
        ExitCode::FAILURE
    })?;
    config.control_socket.ok_or_else(|| {
        eprintln!("server.control_socket is not configured; the admin control socket is disabled");
        ExitCode::FAILURE
    })
}

/// Sends `request` to `control_socket` and returns the daemon's parsed reply. What a reply's
/// `result` means is up to the caller.
fn send_request(control_socket: &Path, request: &control::RpcRequest) -> Result<control::RpcResponse, ExitCode> {
    let mut stream = std::os::unix::net::UnixStream::connect(control_socket).map_err(|err| {
        eprintln!("failed to connect to control socket {}: {err}", control_socket.display());
        ExitCode::FAILURE
    })?;
    stream.set_read_timeout(Some(QUERY_TIMEOUT)).map_err(|err| {
        eprintln!("failed to set a read timeout on the control socket connection: {err}");
        ExitCode::FAILURE
    })?;

    let mut line = serde_json::to_vec(request).expect("RpcRequest contains no types that can fail to serialize");
    line.push(b'\n');
    stream.write_all(&line).map_err(|err| {
        eprintln!("failed to send request: {err}");
        ExitCode::FAILURE
    })?;

    let mut reply = String::new();
    std::io::BufReader::new(&stream).read_line(&mut reply).map_err(|err| {
        eprintln!("failed to read reply: {err}");
        ExitCode::FAILURE
    })?;
    serde_json::from_str(&reply).map_err(|err| {
        eprintln!("received malformed response: {err}");
        ExitCode::FAILURE
    })
}

/// Sends `request`, decodes its result as `T`, and prints it via `print` unless `raw_response` is
/// set, in which case the undecoded JSON is printed instead. `verb` labels the error messages.
fn run_query_command<T: serde::de::DeserializeOwned>(
    control_socket: &Path, request: &control::RpcRequest, verb: &str, raw_response: bool, print: impl FnOnce(&T),
) -> Result<(), ExitCode> {
    let response = send_request(control_socket, request)?;
    let result = response.payload.map_err(|error| {
        eprintln!("{verb} failed: {} (code {})", error.message, error.code.code());
        ExitCode::FAILURE
    })?;
    let value: T = serde_json::from_value(result.clone()).map_err(|err| {
        eprintln!("received malformed {verb} result: {err}");
        ExitCode::FAILURE
    })?;
    if raw_response {
        print_raw_response(&result);
    } else {
        print(&value);
    }
    Ok(())
}

/// Pings `control_socket` and prints the reply.
fn run_ping_command(control_socket: &Path, raw_response: bool) -> Result<(), ExitCode> {
    run_query_command(control_socket, &control::new_ping_request(1), "ping", raw_response, |reply: &String| {
        println!("control socket is up: {reply}");
    })
}

/// Queries `control_socket` for `username`'s status and prints it.
fn run_status_command(control_socket: &Path, username: &str, raw_response: bool) -> Result<(), ExitCode> {
    let request = control::new_limits_sasl_request(username, 1);
    run_query_command(control_socket, &request, "status query", raw_response, |status| {
        print_status(username, status);
    })
}

/// Pretty-prints `result` (a JSON-RPC response's `result` value) verbatim, for `--raw-response`.
fn print_raw_response(result: &serde_json::Value) {
    let pretty = serde_json::to_string_pretty(result).expect("serde_json::Value serialization cannot fail");
    println!("{pretty}");
}

/// Prints `status` for `username`, including each window's live percentage -
/// pure arithmetic, safe to compute here rather than in the daemon.
fn print_status(username: &str, status: &control::StatusResponse) {
    match status {
        control::StatusResponse::Unrestricted { .. } => println!("{username}: unrestricted (no rate limit)"),
        control::StatusResponse::Limited { computed_at, windows } => {
            let computed_at = std::time::UNIX_EPOCH + Duration::from_secs(*computed_at);
            println!("{username}: windows as of {}", humantime::format_rfc3339_seconds(computed_at));
            for window in windows {
                let span = humantime::format_duration(Duration::from_secs(window.span_secs));
                if window.limit == 0 {
                    println!("  {span}: {}/0", window.current_total);
                    continue;
                }
                let percent = 100.0 * f64::from(window.current_total) / f64::from(window.limit);
                println!("  {span}: {}/{} ({percent:.1}%)", window.current_total, window.limit);
            }
        }
    }
}
