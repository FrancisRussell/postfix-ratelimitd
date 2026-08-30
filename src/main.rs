mod config;
mod limiter;
mod protocol;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use clap::Parser;
use config::{Config, FailureAction};
use limiter::Limiter;
use postfix_ratelimitd::{ACTION_DUNNO, ACTION_MISCONFIGURED, ACTION_RATE_LIMITED, ACTION_SERVICE_UNAVAILABLE};
use protocol::{Request, write_action};
use redis::ConnectionInfo;
use tokio::io::BufReader;
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// Where to send log output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum LogTarget {
    /// Formatted lines to stdout, timestamped since nothing else will be -
    /// unlike syslog, nothing here can assume a journald (or other) receiver
    /// is stamping each line for us. The default: safe for local runs,
    /// containers, and anywhere else not necessarily wired to a syslog socket.
    Stdout,
    /// RFC 3164 syslog via /dev/log. Works under journald, which preserves
    /// priority and unit attribution for messages received this way the same
    /// as for native journal capture, or under a standalone rsyslog/syslog-ng.
    /// Unlike a systemd-specific journal integration, this needs nothing
    /// systemd-specific to work.
    Syslog,
}

/// Command-line arguments for the daemon.
#[derive(Debug, Clone, Parser)]
#[command(version, about)]
struct Cli {
    /// Path to the daemon's TOML config file
    #[arg(short, long, default_value = "/etc/postfix-ratelimitd/config.toml")]
    config: PathBuf,

    /// Check the config file and socket directory for validity, then exit
    #[arg(short = 't', long)]
    check_config: bool,

    /// Where to send log output
    #[arg(long, value_enum, default_value_t = LogTarget::Stdout)]
    log_target: LogTarget,

    /// Syslog "ident" prefix on each line; defaults to the binary name.
    /// Ignored unless --log-target=syslog.
    #[arg(long)]
    syslog_ident: Option<String>,
}

/// Expected `protocol_state` for this daemon per its `smtpd_data_restrictions`
/// wiring.
const EXPECTED_PROTOCOL_STATE: &str = "DATA";

/// Owner and group get read-write access, nobody else does - restricting who
/// can reach the socket to whichever group the deploying systemd unit puts
/// this daemon and Postfix in together (see packaging/postfix-ratelimitd.service).
const SOCKET_MODE: u32 = 0o660;
const SOCKET_PROBE_PREFIX: &str = ".rl-check-";

/// Comfortably above realistic load, kept under common fd-limit defaults
/// (~1024) for headroom.
const MAX_CONNECTIONS: usize = 512;
static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Caps how long shutdown waits for connections mid-request to finish;
/// comfortably above how long a single rate-limit check should ever take.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the periodic stats line (see `report_stats`) is printed.
const STATS_INTERVAL: Duration = Duration::from_secs(60);

/// Counts of what's happened since the last periodic stats line - see
/// `report_stats`, which resets every field to 0 each time it reports them.
/// `active_connections` isn't here since it's a live gauge, not something to
/// accumulate - `report_stats` reads `ACTIVE_CONNECTIONS` directly instead.
/// `misconfigured` isn't printed either - a wrong protocol_state or missing
/// recipient_count should never happen in a working deployment, so it exists
/// only to gate `log_throttled` for those two, not as a rate worth reporting.
#[derive(Debug)]
struct Stats {
    accepted: AtomicU64,
    rejected: AtomicU64,
    failed_deferred: AtomicU64,
    failed_permitted: AtomicU64,
    unauthenticated: AtomicU64,
    malformed: AtomicU64,
    misconfigured: AtomicU64,
    connections_accepted: AtomicU64,
    connections_rejected: AtomicU64,
    accept_errors: AtomicU64,
}

static STATS: Stats = Stats {
    accepted: AtomicU64::new(0),
    rejected: AtomicU64::new(0),
    failed_deferred: AtomicU64::new(0),
    failed_permitted: AtomicU64::new(0),
    unauthenticated: AtomicU64::new(0),
    malformed: AtomicU64::new(0),
    misconfigured: AtomicU64::new(0),
    connections_accepted: AtomicU64::new(0),
    connections_rejected: AtomicU64::new(0),
    accept_errors: AtomicU64::new(0),
};

/// Logs one line summarizing `STATS` and the current `ACTIVE_CONNECTIONS`,
/// then resets `STATS` back to 0 for the next interval.
fn report_stats() {
    log::info!(
        "stats interval_secs={} accepted={} rejected={} failed_deferred={} failed_permitted={} unauthenticated={} \
         malformed={} connections_accepted={} connections_rejected={} accept_errors={} active_connections={}",
        STATS_INTERVAL.as_secs(),
        STATS.accepted.swap(0, Ordering::SeqCst),
        STATS.rejected.swap(0, Ordering::SeqCst),
        STATS.failed_deferred.swap(0, Ordering::SeqCst),
        STATS.failed_permitted.swap(0, Ordering::SeqCst),
        STATS.unauthenticated.swap(0, Ordering::SeqCst),
        STATS.malformed.swap(0, Ordering::SeqCst),
        STATS.connections_accepted.swap(0, Ordering::SeqCst),
        STATS.connections_rejected.swap(0, Ordering::SeqCst),
        STATS.accept_errors.swap(0, Ordering::SeqCst),
        ACTIVE_CONNECTIONS.load(Ordering::SeqCst),
    );
    // Not printed (see Stats::misconfigured) - reset here anyway so log_throttled's
    // suppression window still lines up with this same interval.
    STATS.misconfigured.store(0, Ordering::SeqCst);
}

/// How many occurrences of a throttled condition (see `log_throttled`) are
/// logged in full per stats interval before further ones are suppressed
/// until the next report - enough to see a few real examples for diagnosis
/// without flooding under sustained load.
const LOG_SUPPRESSION_LIMIT: u64 = 5;

/// Increments `counter` and calls `log_line` for its first
/// `LOG_SUPPRESSION_LIMIT` occurrences since the last stats report (see
/// `report_stats`, which resets every `STATS` field to 0), then logs one
/// suppression notice naming `kind`, then stays quiet until the next report.
/// `counter` itself keeps counting throughout regardless, so the periodic
/// stats line always reflects the true total even while suppressed.
fn log_throttled(counter: &AtomicU64, kind: &str, log_line: impl FnOnce()) {
    let previous = counter.fetch_add(1, Ordering::SeqCst);
    if previous < LOG_SUPPRESSION_LIMIT {
        log_line();
    } else if previous == LOG_SUPPRESSION_LIMIT {
        log::warn!("suppressing further \"{kind}\" messages until the next stats report");
    }
}

/// Decides the policy action to return for one request.
async fn handle_request(request: &Request, config: &Config, limiter: &Limiter) -> &'static str {
    if request.protocol_state().is_some_and(|state| state != EXPECTED_PROTOCOL_STATE) {
        log_throttled(&STATS.misconfigured, "smtpd_data_restrictions wiring", || {
            log::error!(
                "policy request at protocol_state {:?}, expected {EXPECTED_PROTOCOL_STATE:?} - check \
                 smtpd_data_restrictions wiring; deferring rather than risk enforcing limits against a wrong or \
                 partial recipient_count",
                request.protocol_state()
            );
        });
        return ACTION_MISCONFIGURED;
    }

    let Some(sasl_username) = request.sasl_username() else {
        // Always permitted - there's no identity to rate-limit against - but logged
        // (unless silenced via warn_on_unauthenticated) since it usually means
        // smtpd_data_restrictions is wired somewhere it shouldn't be. The counter
        // always increments either way, so the periodic stats line stays accurate
        // even with warnings silenced or throttled.
        if config.warn_on_unauthenticated {
            log_throttled(&STATS.unauthenticated, "unauthenticated request", || {
                log::warn!("policy request has no SASL username - check this is wired to an authenticated service");
            });
        } else {
            STATS.unauthenticated.fetch_add(1, Ordering::SeqCst);
        }
        return ACTION_DUNNO;
    };
    let Some(recipient_count) = request.recipient_count() else {
        // Same root cause as the protocol_state check above - smtpd_data_restrictions
        // is the only restriction class that populates recipient_count, so a
        // well-wired deployment never reaches this.
        log_throttled(&STATS.misconfigured, "smtpd_data_restrictions wiring", || {
            log::error!(
                "policy request for {sasl_username} is missing recipient_count - check smtpd_data_restrictions \
                 wiring"
            );
        });
        return ACTION_MISCONFIGURED;
    };

    let plan = config.plan_for(sasl_username);
    match limiter.check(sasl_username, recipient_count, plan).await {
        Ok(true) => {
            STATS.accepted.fetch_add(1, Ordering::SeqCst);
            ACTION_DUNNO
        }
        Ok(false) => {
            STATS.rejected.fetch_add(1, Ordering::SeqCst);
            ACTION_RATE_LIMITED
        }
        Err(err) => {
            // A live Valkey outage would otherwise log this once per message for as long as
            // it lasts, at full traffic volume - see log_throttled.
            let (action, counter) = match config.on_redis_error {
                FailureAction::Defer => (ACTION_SERVICE_UNAVAILABLE, &STATS.failed_deferred),
                FailureAction::Permit => (ACTION_DUNNO, &STATS.failed_permitted),
            };
            log_throttled(counter, "valkey error checking rate limit", || {
                log::error!("valkey error checking rate limit for {sasl_username}: {err}");
            });
            action
        }
    }
}

/// Serves policy requests from one Postfix connection until it closes.
///
/// Postfix may hold a connection open, idle, for the rest of an SMTP session
/// after a request completes. So shutdown only races `cancel` against the
/// idle wait for the next request, not against a request already being
/// handled - that always runs to completion.
async fn handle_connection(
    stream: UnixStream, config: Arc<ArcSwap<Config>>, limiter: Arc<ArcSwap<Limiter>>, cancel: CancellationToken,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    loop {
        let request = tokio::select! {
            () = cancel.cancelled() => return,
            result = Request::read_from(&mut reader) => result,
        };
        let request = match request {
            Ok(Some(request)) => request,
            Ok(None) => return,
            Err(err) => {
                log::warn!("error reading policy request: {err}");
                STATS.malformed.fetch_add(1, Ordering::SeqCst);
                return;
            }
        };
        // Loaded fresh per request so a config/limiter reload takes effect on a
        // connection Postfix keeps open across many requests.
        let current_config = config.load_full();
        let current_limiter = limiter.load_full();
        let action = handle_request(&request, &current_config, &current_limiter).await;
        if let Err(err) = write_action(&mut writer, action).await {
            log::warn!("error writing policy response: {err}");
            return;
        }
    }
}

/// Releases its connection's slot in `ACTIVE_CONNECTIONS`, even if the task
/// panics.
struct ConnectionGuard;

impl Drop for ConnectionGuard {
    fn drop(&mut self) { ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::SeqCst); }
}

/// Verifies a unix socket can be created in the socket's directory, without
/// touching the configured socket path itself.
fn check_socket_directory(socket: &std::path::Path) -> std::io::Result<()> {
    let dir = match socket.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => std::path::Path::new("."),
    };
    let probe = dir.join(format!("{SOCKET_PROBE_PREFIX}{}", std::process::id()));
    std::os::unix::net::UnixListener::bind(&probe)?;
    std::fs::remove_file(&probe)
}

/// Logs `message` as an error and exits the process; for unrecoverable startup
/// failures.
fn fatal(message: impl std::fmt::Display) -> ! {
    log::error!("{message}");
    std::process::exit(1);
}

/// Installs the `log` backend `target` selects. Called before anything else
/// in `main`, including config loading, so that even a config-load failure
/// gets logged through the right backend.
fn init_logging(target: LogTarget, syslog_ident: Option<&str>) {
    match target {
        LogTarget::Stdout => env_logger::init(),
        LogTarget::Syslog => {
            let ident = syslog_ident.unwrap_or(env!("CARGO_PKG_NAME")).to_string();
            let formatter = syslog::Formatter3164 {
                facility: syslog::Facility::LOG_DAEMON,
                hostname: None,
                process: ident,
                pid: 0, // the syslog crate's convention for "fill in the real process ID"
            };
            match syslog::unix(formatter) {
                Ok(logger) => {
                    // Mirrors RUST_LOG's simple `<level>` form, since env_logger's fuller
                    // per-module filter syntax isn't reusable outside its own Builder.
                    let level = std::env::var("RUST_LOG")
                        .ok()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(log::LevelFilter::Info);
                    log::set_boxed_logger(Box::new(syslog::BasicLogger::new(logger)))
                        .map(|()| log::set_max_level(level))
                        .expect("no logger installed yet");
                }
                Err(err) => {
                    // env_logger isn't installed yet here, so this can only reach the user via
                    // stderr directly.
                    eprintln!("failed to connect to syslog, falling back to stdout: {err}");
                    env_logger::init();
                }
            }
        }
    }
}

/// Resolves once SIGINT or SIGTERM is received.
async fn shutdown_requested() {
    let mut terminate = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

/// Whether `a` and `b` would make [`Limiter::new`] connect to the same place
/// with the same credentials.
fn same_redis_connection(a: &ConnectionInfo, b: &ConnectionInfo) -> bool {
    let (a_redis, b_redis) = (a.redis_settings(), b.redis_settings());
    a.addr() == b.addr()
        && a_redis.db() == b_redis.db()
        && a_redis.username() == b_redis.username()
        && a_redis.password() == b_redis.password()
        && a_redis.protocol() == b_redis.protocol()
}

/// Handles one SIGHUP: reloads `path` and swaps it into `config`/`limiter` if
/// safe, or logs why not and leaves the daemon running unchanged.
///
/// `server.socket` is fixed at startup - it's the already-bound listener, and
/// nothing short of a restart can rebind it. A changed redis connection or
/// key prefix instead triggers rebuilding `Limiter` against the new settings;
/// that only succeeds if the new one actually connects, and if it doesn't,
/// the whole reload is rejected (nothing swaps) so `config` can never
/// disagree with the `Limiter` actually in use.
async fn reload_config(path: &std::path::Path, config: &ArcSwap<Config>, limiter: &ArcSwap<Limiter>) {
    let current = config.load_full();
    let new_config = match Config::load(path) {
        Ok(config) => config,
        Err(err) => {
            log::error!("not reloading config {}: {err}", path.display());
            return;
        }
    };

    if new_config.socket != current.socket {
        log::error!("not reloading config: `socket` changed, which requires a restart to take effect");
        return;
    }

    if !same_redis_connection(&new_config.redis_connection_info, &current.redis_connection_info)
        || new_config.redis_key_prefix != current.redis_key_prefix
    {
        match Limiter::new(new_config.redis_connection_info.clone(), new_config.redis_key_prefix.clone()).await {
            Ok(new_limiter) => limiter.store(Arc::new(new_limiter)),
            Err(err) => {
                log::error!("not reloading config: failed to connect with the new redis settings: {err}");
                return;
            }
        }
    }

    config.store(Arc::new(new_config));
    log::info!("reloaded config from {}", path.display());
}

/// Loads the config, binds the policy socket, and serves connections until
/// killed.
#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_logging(cli.log_target, cli.syslog_ident.as_deref());

    let config = match Config::load(&cli.config) {
        Ok(config) => config,
        Err(err) => fatal(format!("failed to load config {}: {err}", cli.config.display())),
    };

    if cli.check_config {
        if let Err(err) = check_socket_directory(&config.socket) {
            fatal(format!("socket directory check failed for {}: {err}", config.socket.display()));
        }
        println!("config OK: {}", cli.config.display());
        return;
    }

    let limiter = match Limiter::new(config.redis_connection_info.clone(), config.redis_key_prefix.clone()).await {
        Ok(limiter) => limiter,
        Err(err) => fatal(format!("failed to initialize valkey client: {err}")),
    };

    if let Err(err) = std::fs::remove_file(&config.socket)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        fatal(format!("failed to remove stale socket {}: {err}", config.socket.display()));
    }

    let listener = match UnixListener::bind(&config.socket) {
        Ok(listener) => listener,
        Err(err) => fatal(format!("failed to bind socket {}: {err}", config.socket.display())),
    };
    // Access control is the install-time socket directory's job, not this file's.
    if let Err(err) = std::fs::set_permissions(&config.socket, std::fs::Permissions::from_mode(SOCKET_MODE)) {
        fatal(format!("failed to set permissions on socket {}: {err}", config.socket.display()));
    }

    log::info!("listening on {}", config.socket.display());

    tokio::spawn(async {
        let mut interval = tokio::time::interval(STATS_INTERVAL);
        interval.tick().await; // fires immediately; skip so the first report covers a full interval
        loop {
            interval.tick().await;
            report_stats();
        }
    });

    let config = Arc::new(ArcSwap::from_pointee(config));
    let limiter = Arc::new(ArcSwap::from_pointee(limiter));
    let reload_in_progress = Arc::new(AtomicBool::new(false));
    let reload_requests = Arc::new(AtomicU64::new(0));
    let shutdown = shutdown_requested();
    tokio::pin!(shutdown);
    let mut reload_signal = signal(SignalKind::hangup()).expect("install SIGHUP handler");
    let cancel = CancellationToken::new();
    let tracker = TaskTracker::new();

    loop {
        let stream = tokio::select! {
            result = listener.accept() => match result {
                Ok((stream, _addr)) => stream,
                Err(err) => {
                    log::warn!("failed to accept connection: {err}");
                    STATS.accept_errors.fetch_add(1, Ordering::SeqCst);
                    // Avoids busy-looping if accept() is persistently failing, e.g. out of file
                    // descriptors.
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                }
            },
            () = &mut shutdown => {
                log::info!("shutdown requested, no longer accepting connections");
                break;
            }
            _ = reload_signal.recv() => {
                // Spawned rather than awaited here, so a slow reconnect attempt against new
                // redis settings can't stall accepting new connections. reload_in_progress caps
                // concurrent reload attempts at one; a SIGHUP that arrives mid-reload isn't
                // dropped, though - it bumps reload_requests, and the running worker notices
                // that on its next pass and reloads again rather than exiting on a config that
                // was already superseded while it worked.
                reload_requests.fetch_add(1, Ordering::SeqCst);
                if !reload_in_progress.swap(true, Ordering::SeqCst) {
                    let path = cli.config.clone();
                    let config = Arc::clone(&config);
                    let limiter = Arc::clone(&limiter);
                    let reload_in_progress = Arc::clone(&reload_in_progress);
                    let reload_requests = Arc::clone(&reload_requests);
                    tokio::spawn(async move {
                        loop {
                            let generation = reload_requests.load(Ordering::SeqCst);
                            reload_config(&path, &config, &limiter).await;
                            if reload_requests.load(Ordering::SeqCst) == generation {
                                break;
                            }
                            log::info!("config changed again mid-reload, reloading once more");
                        }
                        reload_in_progress.store(false, Ordering::SeqCst);
                    });
                }
                continue;
            }
        };

        if ACTIVE_CONNECTIONS.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::SeqCst);
            // This has no backoff of its own, unlike the accept() failure path below, so a
            // sustained overload would otherwise log once per connection attempt for as
            // long as it lasts - see log_throttled.
            log_throttled(&STATS.connections_rejected, "concurrent connection limit rejection", || {
                log::warn!("rejecting connection: at the concurrent connection limit ({MAX_CONNECTIONS})");
            });
            continue;
        }
        STATS.connections_accepted.fetch_add(1, Ordering::SeqCst);

        let config = Arc::clone(&config);
        let limiter = Arc::clone(&limiter);
        let cancel = cancel.clone();
        tracker.spawn(async move {
            let _guard = ConnectionGuard;
            handle_connection(stream, config, limiter, cancel).await;
        });
    }

    cancel.cancel();
    tracker.close();
    if tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, tracker.wait()).await.is_err() {
        log::warn!("timed out waiting for in-flight connections to close during shutdown");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_throttled_calls_log_line_up_to_the_limit_then_suppresses() {
        let counter = AtomicU64::new(0);
        let mut calls = 0;
        for _ in 0..LOG_SUPPRESSION_LIMIT * 2 {
            log_throttled(&counter, "test", || calls += 1);
        }
        assert_eq!(calls, LOG_SUPPRESSION_LIMIT, "log_line should fire exactly LOG_SUPPRESSION_LIMIT times");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            LOG_SUPPRESSION_LIMIT * 2,
            "the counter must keep counting even while suppressed"
        );
    }
}
