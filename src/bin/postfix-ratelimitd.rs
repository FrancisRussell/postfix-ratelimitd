#![warn(clippy::pedantic)]
#![deny(unsafe_code)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use clap::Parser;
use postfix_ratelimitd::config::{Config, FailureAction};
use postfix_ratelimitd::limiter::Limiter;
use postfix_ratelimitd::protocol::{Request, write_action};
use postfix_ratelimitd::state::RuntimeState;
use postfix_ratelimitd::{
    ACTION_DUNNO, ACTION_MISCONFIGURED, ACTION_RATE_LIMITED, ACTION_SERVICE_UNAVAILABLE, control,
};
use redis::ConnectionInfo;
use tokio::io::BufReader;
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// Where to send log output.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum LogTarget {
    /// Timestamped lines to stdout
    Stdout,
    /// RFC 3164 syslog via /dev/log
    // Also works under journald, which preserves priority and unit attribution for messages received this way the same
    // as for native journal capture.
    Syslog,
}

#[derive(Debug, Clone, Parser)]
#[command(version, about)]
struct Cli {
    /// Path to the daemon's TOML config file
    #[arg(short, long, default_value = postfix_ratelimitd::config::DEFAULT_CONFIG_PATH)]
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

    /// Minimum severity to log: OFF, ERROR, WARN, INFO, DEBUG, or TRACE (case-insensitive)
    #[arg(long, default_value_t = log::LevelFilter::Info)]
    log_level: log::LevelFilter,
}

/// Protocol states this daemon accepts requests at, per its `smtpd_data_restrictions`/`smtpd_end_of_data_restrictions`
/// wiring. Both populate `recipient_count` with the message's final total, differing only in whether Postfix has
/// already accepted the message body (END-OF-MESSAGE) or not yet.
const EXPECTED_PROTOCOL_STATES: [&str; 2] = ["DATA", "END-OF-MESSAGE"];

/// Owner and group get read-write access.
const SOCKET_MODE: u32 = 0o660;

/// Owner-only - unlike `SOCKET_MODE`, the control socket must not be
/// reachable via Postfix's membership in the runtime directory's group.
const CONTROL_SOCKET_MODE: u32 = 0o600;

const SOCKET_PROBE_PREFIX: &str = ".rl-check-";

/// Suffix naming this instance's startup lock file (see
/// `acquire_startup_lock`), in the same directory as `server.socket`.
const LOCK_FILE_SUFFIX: &str = ".lock";

/// Forces a freshly created socket's default mode to owner-only, regardless
/// of the ambient umask, by clearing every group/other bit a `bind()` call
/// could otherwise leave set - see its use around the socket bind for why.
const SOCKET_CREATE_UMASK: u32 = 0o177;

/// Comfortably above realistic load, kept under common fd-limit defaults
/// (~1024) for headroom.
const MAX_CONNECTIONS: usize = 512;
static ACTIVE_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Caps how long shutdown waits for connections mid-request to finish;
/// comfortably above how long a single rate-limit check should ever take.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the periodic stats line (see `report_stats`) is printed.
const STATS_INTERVAL: Duration = Duration::from_mins(1);

/// Counts of what's happened since the last periodic stats line. `active_connections` isn't here since it's a live
/// gauge.
#[derive(Debug, Default)]
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

static STATS: LazyLock<Stats> = LazyLock::new(Stats::default);

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
    // misconfigured isn't part of the printed line above. It's still reset
    // here so its log_throttled suppression window lines up with this interval.
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
    if request.protocol_state().is_some_and(|state| !EXPECTED_PROTOCOL_STATES.contains(&state)) {
        log_throttled(&STATS.misconfigured, "smtpd_data_restrictions/smtpd_end_of_data_restrictions wiring", || {
            log::error!(
                "policy request at protocol_state {:?}, expected one of {EXPECTED_PROTOCOL_STATES:?} - check \
                 smtpd_data_restrictions/smtpd_end_of_data_restrictions wiring; deferring rather than risk \
                 enforcing limits against a wrong or partial recipient_count",
                request.protocol_state()
            );
        });
        return ACTION_MISCONFIGURED;
    }

    let Some(sasl_username) = request.sasl_username() else {
        // Unauthenticated messages are always permitted but logged (unless silenced via warn_on_unauthenticated) since
        // it usually means this is wired somewhere it shouldn't be. The counter always increments either way, so the
        // periodic stats line stays accurate even with warnings silenced or throttled.
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
        // Same root cause as the protocol_state check above - DATA and END-OF-MESSAGE
        // are the only protocol states that populate recipient_count, so a
        // well-wired deployment never reaches this.
        log_throttled(&STATS.misconfigured, "smtpd_data_restrictions/smtpd_end_of_data_restrictions wiring", || {
            log::error!(
                "policy request for {sasl_username} is missing recipient_count - check \
                 smtpd_data_restrictions/smtpd_end_of_data_restrictions wiring"
            );
        });
        return ACTION_MISCONFIGURED;
    };

    let plan = config.plan_for(sasl_username);
    match limiter.check_sasl(sasl_username, recipient_count, plan, request.now_override()).await {
        Ok(true) => {
            STATS.accepted.fetch_add(1, Ordering::SeqCst);
            log::debug!("accepted {sasl_username}: {recipient_count} recipients");
            ACTION_DUNNO
        }
        Ok(false) => {
            STATS.rejected.fetch_add(1, Ordering::SeqCst);
            log::debug!("rejected {sasl_username}: {recipient_count} recipients over limit");
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
async fn handle_connection(stream: UnixStream, state: Arc<ArcSwap<RuntimeState>>, cancel: CancellationToken) {
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
        let current = state.load_full();
        let action = handle_request(&request, &current.config, &current.limiter).await;
        if let Err(err) = write_action(&mut writer, action).await {
            log::warn!("error writing policy response: {err}");
            return;
        }
    }
}

/// Which listener a connection accepted from, so the caller can dispatch it
/// to the matching handler after the two accept arms in the main loop's
/// `select!` join back into one path.
#[derive(Debug)]
enum Accepted {
    Policy(UnixStream),
    Control(UnixStream),
}

/// Polls `listener`'s `accept()`, or never resolves if `listener` is `None` -
/// so a `select!` arm built from this never fires while the control socket
/// is disabled, without special-casing the loop itself.
async fn accept_control(listener: Option<&UnixListener>) -> std::io::Result<UnixStream> {
    match listener {
        Some(listener) => listener.accept().await.map(|(stream, _addr)| stream),
        None => std::future::pending().await,
    }
}

/// Releases its connection's slot in `ACTIVE_CONNECTIONS`, even if the task
/// panics.
#[derive(Debug)]
struct ConnectionGuard;

impl Drop for ConnectionGuard {
    fn drop(&mut self) { ACTIVE_CONNECTIONS.fetch_sub(1, Ordering::SeqCst); }
}

/// Verifies a unix socket can be created in the socket's directory, without
/// touching the configured socket path itself.
fn check_socket_directory(socket: &Path) -> std::io::Result<()> {
    let dir = match socket.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let probe = dir.join(format!("{SOCKET_PROBE_PREFIX}{}", std::process::id()));
    std::os::unix::net::UnixListener::bind(&probe)?;
    std::fs::remove_file(&probe)
}

/// Acquires an exclusive, non-blocking lock on `socket`'s lock file. The
/// lock is tied to the open file, not the path. It's never released
/// explicitly. Closing this process's handle on it frees the lock
/// automatically, letting a later instance safely relock the same path.
fn acquire_startup_lock(socket: &Path) -> std::io::Result<std::fs::File> {
    let mut lock_path = socket.as_os_str().to_owned();
    lock_path.push(LOCK_FILE_SUFFIX);
    let file = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(&lock_path)?;
    file.try_lock()?;
    Ok(file)
}

/// Whether another process is already listening on `socket`. A successful
/// connect is a live signal; a permission error can't tell live from stale,
/// so it's treated as live too rather than risk removing a real listener's
/// socket on an unverifiable guess. Every other error means it's safe to
/// remove and rebind.
fn socket_is_live(socket: &Path) -> bool {
    match std::os::unix::net::UnixStream::connect(socket) {
        Ok(_) => true,
        Err(err) => err.kind() == std::io::ErrorKind::PermissionDenied,
    }
}

/// Logs `message` for an unrecoverable startup failure and returns the
/// failure `ExitCode` for `main` to return.
fn fatal(message: impl std::fmt::Display) -> ExitCode {
    log::error!("{message}");
    ExitCode::FAILURE
}

/// As [`acquire_startup_lock`], but already turned into the `ExitCode` `main` should return on
/// failure - shared since both the policy and control sockets need their own instance of this
/// exact same guard.
fn acquire_startup_lock_or_fatal(socket: &Path) -> Result<std::fs::File, ExitCode> {
    acquire_startup_lock(socket).map_err(|err| {
        if err.kind() == std::io::ErrorKind::WouldBlock {
            fatal(format!("refusing to start: the startup lock for {} is already held", socket.display()))
        } else {
            fatal(format!("failed to acquire startup lock for {}: {err}", socket.display()))
        }
    })
}

/// Binds `socket` at `mode`, removing any stale (non-live) file at that path first. Shared
/// between the policy and control sockets, which differ only in path and mode.
fn bind_socket(socket: &Path, mode: u32) -> Result<UnixListener, ExitCode> {
    if socket_is_live(socket) {
        return Err(fatal(format!(
            "refusing to start: {} is already in use by another process, or its permissions couldn't be verified",
            socket.display()
        )));
    }
    if let Err(err) = std::fs::remove_file(socket)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        return Err(fatal(format!("failed to remove stale socket {}: {err}", socket.display())));
    }

    // A freshly bound socket briefly exists at bind()'s own default mode until the chmod below
    // narrows it to `mode` - narrowing the umask first (see SOCKET_CREATE_UMASK) makes that
    // default owner-only regardless of the ambient umask, so the window is only ever more
    // restrictive than `mode`, never less.
    // umask is process-wide state, not scoped to this thread, so this would be unsound to leave
    // narrowed around anything that creates files without an explicit mode of its own on another
    // task - nothing between the two umask calls here does that, only the bind() itself.
    let previous_umask = set_umask(SOCKET_CREATE_UMASK);
    let listener = UnixListener::bind(socket);
    set_umask(previous_umask);
    let listener = match listener {
        Ok(listener) => listener,
        Err(err) => return Err(fatal(format!("failed to bind socket {}: {err}", socket.display()))),
    };
    if let Err(err) = std::fs::set_permissions(socket, std::fs::Permissions::from_mode(mode)) {
        return Err(fatal(format!("failed to set permissions on socket {}: {err}", socket.display())));
    }
    Ok(listener)
}

/// Installs the `log` backend `target` selects, filtered to `level`. Called
/// before anything else in `main`, including config loading, so that even a
/// config-load failure gets logged through the right backend.
fn init_logging(target: LogTarget, syslog_ident: Option<&str>, level: log::LevelFilter) {
    match target {
        LogTarget::Stdout => env_logger::Builder::new().filter_level(level).init(),
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
                    log::set_boxed_logger(Box::new(syslog::BasicLogger::new(logger)))
                        .map(|()| log::set_max_level(level))
                        .expect("no logger installed yet");
                }
                Err(err) => {
                    // env_logger isn't installed yet here, so this can only reach the user via
                    // stderr directly.
                    eprintln!("failed to connect to syslog, falling back to stdout: {err}");
                    env_logger::Builder::new().filter_level(level).init();
                }
            }
        }
    }
}

/// Resolves once SIGINT or SIGTERM is received.
async fn shutdown_requested(terminate: &mut Signal) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

/// Whether `a` and `b` would make [`Limiter::new`] connect to the same place
/// with the same credentials. `ConnectionInfo` has no `PartialEq` of its own
/// to defer to, and a derived one wouldn't fit anyway: it would also compare
/// fields like `lib_name`/`lib_ver` that have no bearing on whether reload
/// can skip rebuilding `Limiter`.
fn same_redis_connection(a: &ConnectionInfo, b: &ConnectionInfo) -> bool {
    let (a_redis, b_redis) = (a.redis_settings(), b.redis_settings());
    a.addr() == b.addr()
        && a_redis.db() == b_redis.db()
        && a_redis.username() == b_redis.username()
        && a_redis.password() == b_redis.password()
        && a_redis.protocol() == b_redis.protocol()
}

/// Handles one SIGHUP: reloads `path` and swaps it into `state` if safe, or
/// logs why not and leaves the daemon running unchanged.
///
/// `server.socket` is fixed at startup - it's the already-bound listener, and
/// nothing short of a restart can rebind it. A changed redis connection or
/// key prefix instead triggers rebuilding `Limiter` against the new settings;
/// that only succeeds if the new one actually connects, and if it doesn't,
/// the whole reload is rejected (nothing swaps). Either way, `state` is
/// replaced with one `store()` carrying both the new config and its matching
/// limiter together, so a reader can never observe one paired with a stale
/// version of the other.
async fn reload_config(path: &Path, state: &ArcSwap<RuntimeState>) {
    let current = state.load_full();
    let new_config = match Config::load(path) {
        Ok(config) => config,
        Err(err) => {
            log::error!("not reloading config {}: {err}", path.display());
            return;
        }
    };

    if new_config.socket != current.config.socket {
        log::error!("not reloading config: `socket` changed, which requires a restart to take effect");
        return;
    }

    if new_config.control_socket != current.config.control_socket {
        log::error!("not reloading config: `control_socket` changed, which requires a restart to take effect");
        return;
    }

    let new_limiter =
        if !same_redis_connection(&new_config.redis_connection_info, &current.config.redis_connection_info)
            || new_config.redis_key_prefix != current.config.redis_key_prefix
        {
            match Limiter::new(new_config.redis_connection_info.clone(), new_config.redis_key_prefix.clone()).await {
                Ok(new_limiter) => new_limiter,
                Err(err) => {
                    log::error!("not reloading config: failed to connect with the new redis settings: {err}");
                    return;
                }
            }
        } else {
            current.limiter.clone()
        };

    state.store(Arc::new(RuntimeState { config: new_config, limiter: new_limiter }));
    log::info!("reloaded config from {}", path.display());
}

/// Sets the process umask, returning the previous one.
///
/// SAFETY: `umask(2)` only reads and writes process-wide umask state - it
/// can't invalidate anything else, regardless of what else is running
/// concurrently.
#[allow(unsafe_code)]
fn set_umask(mask: u32) -> u32 { unsafe { libc::umask(mask) } }

/// Loads the config, binds the policy socket, and serves connections until
/// killed.
#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> ExitCode {
    // Refuse to run at all if this is an integration test build unless explicitly acknowledged.
    #[cfg(feature = "integration-tests")]
    if std::env::var(postfix_ratelimitd::INTEGRATION_TEST_ACKNOWLEDGMENT_ENV_VAR).is_err() {
        eprintln!(
            "built with the integration-tests feature, which must never run in production - set \
             {} to acknowledge this is a test build",
            postfix_ratelimitd::INTEGRATION_TEST_ACKNOWLEDGMENT_ENV_VAR
        );
        return ExitCode::FAILURE;
    }

    let cli = Cli::parse();
    init_logging(cli.log_target, cli.syslog_ident.as_deref(), cli.log_level);

    let config = match Config::load(&cli.config) {
        Ok(config) => config,
        Err(err) => return fatal(format!("failed to load config {}: {err}", cli.config.display())),
    };

    if cli.check_config {
        for socket in [Some(&config.socket), config.control_socket.as_ref()].into_iter().flatten() {
            if let Err(err) = check_socket_directory(socket) {
                return fatal(format!("socket directory check failed for {}: {err}", socket.display()));
            }
        }
        println!("config OK: {}", cli.config.display());
        return ExitCode::SUCCESS;
    }

    // Held for this instance's entire run, including its shutdown drain. It's acquired before
    // connecting to Redis, so a redundant instance fails fast rather than paying for a
    // connection it was always going to discard. A second lock guards `control_socket`
    // separately, for the case where two different configs happen to name the same one -
    // the first lock alone only catches two instances sharing `socket`.
    let _startup_lock = match acquire_startup_lock_or_fatal(&config.socket) {
        Ok(lock) => lock,
        Err(code) => return code,
    };
    let _control_startup_lock = match &config.control_socket {
        Some(control_socket) => match acquire_startup_lock_or_fatal(control_socket) {
            Ok(lock) => Some(lock),
            Err(code) => return code,
        },
        None => None,
    };

    let limiter = match Limiter::new(config.redis_connection_info.clone(), config.redis_key_prefix.clone()).await {
        Ok(limiter) => limiter,
        Err(err) => return fatal(format!("failed to initialize valkey client: {err}")),
    };

    // Access control beyond this is the install-time socket directory's job, not this file's -
    // SOCKET_MODE/CONTROL_SOCKET_MODE only need to be as tight as each socket's own intended
    // audience requires (shared with Postfix's group, or owner-only), not to substitute for the
    // directory's own restriction.
    let listener = match bind_socket(&config.socket, SOCKET_MODE) {
        Ok(listener) => listener,
        Err(code) => return code,
    };
    log::info!("listening on {}", config.socket.display());

    let control_listener = match &config.control_socket {
        Some(control_socket) => match bind_socket(control_socket, CONTROL_SOCKET_MODE) {
            Ok(listener) => {
                log::info!("listening for control connections on {}", control_socket.display());
                Some(listener)
            }
            Err(code) => return code,
        },
        None => None,
    };

    tokio::spawn(async {
        let mut interval = tokio::time::interval(STATS_INTERVAL);
        interval.tick().await; // fires immediately; skip so the first report covers a full interval
        loop {
            interval.tick().await;
            report_stats();
        }
    });

    let state = Arc::new(ArcSwap::from_pointee(RuntimeState { config, limiter }));
    let reload_in_progress = Arc::new(AtomicBool::new(false));
    let reload_requests = Arc::new(AtomicU64::new(0));
    let mut terminate_signal = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(err) => return fatal(format!("failed to install SIGTERM handler: {err}")),
    };
    let mut reload_signal = match signal(SignalKind::hangup()) {
        Ok(signal) => signal,
        Err(err) => return fatal(format!("failed to install SIGHUP handler: {err}")),
    };
    let shutdown = shutdown_requested(&mut terminate_signal);
    tokio::pin!(shutdown);
    let cancel = CancellationToken::new();
    let tracker = TaskTracker::new();

    loop {
        let accepted = tokio::select! {
            result = listener.accept() => match result {
                Ok((stream, _addr)) => Accepted::Policy(stream),
                Err(err) => {
                    log::warn!("failed to accept connection: {err}");
                    STATS.accept_errors.fetch_add(1, Ordering::SeqCst);
                    // Avoids busy-looping if accept() is persistently failing, e.g. out of file
                    // descriptors.
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                }
            },
            result = accept_control(control_listener.as_ref()) => match result {
                Ok(stream) => Accepted::Control(stream),
                Err(err) => {
                    log::warn!("failed to accept control connection: {err}");
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
                // dropped. Instead it bumps reload_requests, and the running worker notices
                // that on its next pass and reloads again rather than exiting on a config that
                // was already superseded while it worked.
                reload_requests.fetch_add(1, Ordering::SeqCst);
                if !reload_in_progress.swap(true, Ordering::SeqCst) {
                    let path = cli.config.clone();
                    let state = Arc::clone(&state);
                    let reload_in_progress = Arc::clone(&reload_in_progress);
                    let reload_requests = Arc::clone(&reload_requests);
                    tokio::spawn(async move {
                        loop {
                            let generation = reload_requests.load(Ordering::SeqCst);
                            reload_config(&path, &state).await;
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
            // Both socket types share this one fd budget, but only a policy-socket rejection
            // counts toward STATS.connections_rejected, matching connections_accepted below
            // being policy-only - so connections_accepted + connections_rejected keeps meaning
            // "all policy-socket accept outcomes", not diluted by admin traffic.
            match &accepted {
                Accepted::Policy(_) => {
                    // This has no backoff of its own, unlike the accept() failure path below, so
                    // a sustained overload would otherwise log once per connection attempt for
                    // as long as it lasts - see log_throttled.
                    log_throttled(&STATS.connections_rejected, "concurrent connection limit rejection", || {
                        log::warn!("rejecting connection: at the concurrent connection limit ({MAX_CONNECTIONS})");
                    });
                }
                Accepted::Control(_) => {
                    log::warn!("rejecting control connection: at the concurrent connection limit ({MAX_CONNECTIONS})");
                }
            }
            continue;
        }

        let state = Arc::clone(&state);
        let cancel = cancel.clone();
        match accepted {
            Accepted::Policy(stream) => {
                STATS.connections_accepted.fetch_add(1, Ordering::SeqCst);
                tracker.spawn(async move {
                    let _guard = ConnectionGuard;
                    handle_connection(stream, state, cancel).await;
                });
            }
            Accepted::Control(stream) => {
                tracker.spawn(async move {
                    let _guard = ConnectionGuard;
                    control::handle_connection(stream, state, cancel).await;
                });
            }
        }
    }

    cancel.cancel();
    tracker.close();
    if tokio::time::timeout(SHUTDOWN_DRAIN_TIMEOUT, tracker.wait()).await.is_err() {
        log::warn!("timed out waiting for in-flight connections to close during shutdown");
    }
    ExitCode::SUCCESS
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
