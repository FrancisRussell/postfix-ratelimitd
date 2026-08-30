#![cfg(feature = "integration-tests")]

//! Exercises the compiled daemon binary end-to-end against a throwaway
//! `valkey-server` instance this test spawns itself (unix-socket only,
//! ephemeral tempdir, no persistence) - never the system service, so these
//! tests need no privileges beyond running the `valkey-server` binary and never
//! touch anything but their own private instance.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use postfix_ratelimitd::config::BUCKET_TARGET_COUNT;
use postfix_ratelimitd::{ACTION_DUNNO, ACTION_MISCONFIGURED, ACTION_RATE_LIMITED, ACTION_SERVICE_UNAVAILABLE};

/// How long to wait for a spawned `valkey-server` or daemon to become ready.
const READY_TIMEOUT: Duration = Duration::from_secs(5);

/// How often to poll while waiting for readiness.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// How a [`ValkeyInstance`] can be reached.
#[derive(Debug, Clone)]
enum Transport {
    Unix {
        socket: std::path::PathBuf,
    },
    Tcp {
        port: u16,
    },
    /// `plain_port` is a second, plaintext port on the same instance, used
    /// only by this test harness itself (readiness checks, keyspace
    /// inspection) so the harness never needs to trust the throwaway CA
    /// issued for `port`.
    Tls {
        port: u16,
        plain_port: u16,
    },
}

/// A throwaway `valkey-server` instance, reachable only via `transport`, in its
/// own tempdir.
#[derive(Debug)]
struct ValkeyInstance {
    child: Child,
    transport: Transport,
    tls_ca_cert: Option<std::path::PathBuf>,
    _dir: tempfile::TempDir,
}

/// Throwaway CA/certificate/key checked into `tests/tls-fixtures/` (generated
/// by `generate.sh` there) for the TLS test - not secrets, and not used
/// outside this repo's own test suite.
const TLS_FIXTURE_CA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/tls-fixtures/ca.crt");
const TLS_FIXTURE_CERT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/tls-fixtures/server.crt");
const TLS_FIXTURE_KEY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/tls-fixtures/server.key");

/// Asks the OS for a free TCP port by binding to port 0, then releasing it;
/// there's a small, unavoidable window before `valkey-server` binds it where
/// another process could take it - standard practice for test harnesses, and
/// not worth engineering around here.
fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port").local_addr().expect("local addr").port()
}

impl ValkeyInstance {
    /// Starts a `valkey-server` reachable only via a unix socket in its own
    /// tempdir.
    fn start_unix() -> ValkeyInstance {
        let dir = tempfile::tempdir().expect("create temp dir");
        let socket = dir.path().join("valkey.sock");
        let socket_str = socket.to_str().expect("temp dir path is valid UTF-8");
        let child = Self::spawn(&dir, &["--port", "0", "--unixsocket", socket_str]);
        let mut instance =
            ValkeyInstance { child, transport: Transport::Unix { socket }, tls_ca_cert: None, _dir: dir };
        instance.wait_until_ready();
        instance
    }

    /// Starts a `valkey-server` reachable only via TCP on an OS-assigned
    /// loopback port.
    fn start_tcp() -> ValkeyInstance {
        let dir = tempfile::tempdir().expect("create temp dir");
        let port = free_tcp_port();
        let child = Self::spawn(&dir, &["--port", &port.to_string(), "--bind", "127.0.0.1"]);
        let mut instance = ValkeyInstance { child, transport: Transport::Tcp { port }, tls_ca_cert: None, _dir: dir };
        instance.wait_until_ready();
        instance
    }

    /// Starts a `valkey-server` reachable via TLS (using the checked-in
    /// fixture cert) on one OS-assigned port, plus a second, plaintext,
    /// OS-assigned port this test harness itself uses for readiness checks
    /// and keyspace inspection.
    fn start_tls() -> ValkeyInstance {
        let dir = tempfile::tempdir().expect("create temp dir");
        let plain_port = free_tcp_port();
        let tls_port = free_tcp_port();
        let child = Self::spawn(
            &dir,
            &[
                "--bind",
                "127.0.0.1",
                "--port",
                &plain_port.to_string(),
                "--tls-port",
                &tls_port.to_string(),
                "--tls-cert-file",
                TLS_FIXTURE_CERT,
                "--tls-key-file",
                TLS_FIXTURE_KEY,
                "--tls-ca-cert-file",
                TLS_FIXTURE_CA,
                "--tls-auth-clients",
                "no",
            ],
        );
        let mut instance = ValkeyInstance {
            child,
            transport: Transport::Tls { port: tls_port, plain_port },
            tls_ca_cert: Some(TLS_FIXTURE_CA.into()),
            _dir: dir,
        };
        instance.wait_until_ready();
        instance
    }

    /// Spawns `valkey-server` with `transport_args` plus settings common to
    /// every instance.
    fn spawn(dir: &tempfile::TempDir, transport_args: &[&str]) -> Child {
        Command::new("valkey-server")
            .args(transport_args)
            .arg("--daemonize")
            .arg("no")
            .arg("--dir")
            .arg(dir.path())
            .arg("--save")
            .arg("")
            .arg("--appendonly")
            .arg("no")
            .arg("--logfile")
            .arg(dir.path().join("valkey.log"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn valkey-server (is it installed and on PATH?)")
    }

    /// The `redis_url` a daemon should use to reach this instance.
    fn redis_url(&self) -> String {
        match &self.transport {
            Transport::Unix { socket } => format!("redis+unix://{}", socket.display()),
            Transport::Tcp { port } => format!("redis://127.0.0.1:{port}"),
            Transport::Tls { port, .. } => format!("rediss://127.0.0.1:{port}"),
        }
    }

    /// The URL this test harness itself uses to poll readiness or inspect the
    /// keyspace directly - always plaintext, even for a `Tls` instance, so the
    /// harness never needs to trust its throwaway CA.
    fn harness_url(&self) -> String {
        match &self.transport {
            Transport::Tls { plain_port, .. } => format!("redis://127.0.0.1:{plain_port}"),
            _ => self.redis_url(),
        }
    }

    /// The CA cert path a daemon connecting via TLS must be told to trust.
    fn tls_ca_cert(&self) -> &std::path::Path { self.tls_ca_cert.as_deref().expect("only set for a Tls instance") }

    /// Blocks until this instance answers PING, or panics after
    /// [`READY_TIMEOUT`].
    fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            if let Ok(client) = redis::Client::open(self.harness_url())
                && let Ok(mut connection) = client.get_connection()
                && redis::cmd("PING").query::<String>(&mut connection).is_ok()
            {
                return;
            }
            assert!(Instant::now() < deadline, "valkey-server did not become ready in time");
            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// Opens a fresh connection to this instance, for tests to inspect its
    /// keyspace directly.
    fn connection(&self) -> redis::Connection {
        redis::Client::open(self.harness_url()).expect("open redis client").get_connection().expect("connect")
    }

    /// The current bucket id for `bucket_size_secs`, computed from this
    /// instance's own clock the same way `check_and_record.lua` does - so
    /// tests can seed a key's state directly instead of waiting in real time
    /// for buckets to age.
    fn current_bucket(&self, bucket_size_secs: u64) -> u64 {
        let mut connection = self.connection();
        let time: Vec<String> = redis::cmd("TIME").query(&mut connection).expect("TIME");
        let now: u64 = time[0].parse().expect("TIME seconds");
        now / bucket_size_secs
    }

    /// Keys matching `pattern` right now. Tests use this instead of a
    /// hardcoded key name (which encodes a bucket size this daemon computed,
    /// not one the test chose) so a change to that computation makes the
    /// assertion fail loudly rather than silently checking the wrong - or an
    /// always-empty - key and passing anyway.
    fn keys(&self, pattern: &str) -> Vec<String> {
        let mut connection = self.connection();
        redis::cmd("KEYS").arg(pattern).query(&mut connection).expect("keys")
    }
}

impl Drop for ValkeyInstance {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A running daemon instance and its temp config/socket, cleaned up on drop.
#[derive(Debug)]
struct Daemon {
    child: Child,
    socket: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

impl Daemon {
    /// Starts the compiled daemon pointed at `valkey`, with `extra_config`
    /// appended to a minimal base config, waiting for its socket to appear
    /// before returning.
    fn start(valkey: &ValkeyInstance, extra_config: &str) -> Daemon { Self::start_with_env(valkey, extra_config, &[]) }

    /// As [`Daemon::start`], but with `env` set on the daemon's process - for
    /// e.g. pointing `SSL_CERT_FILE` at a throwaway CA.
    fn start_with_env(valkey: &ValkeyInstance, extra_config: &str, env: &[(&str, &str)]) -> Daemon {
        let dir = tempfile::tempdir().expect("create temp dir");
        let socket = dir.path().join("policy.sock");
        let config_path = dir.path().join("config.toml");
        // Dotted keys, not `[redis]`/`[server]` headers, so `extra_config` can add more
        // keys to either table (e.g. `redis.key_prefix`, `server.on_redis_error`)
        // without TOML rejecting it as redefining an already-closed table.
        std::fs::write(
            &config_path,
            format!(
                "redis.url = \"{}\"\n\
                 redis.db = 0\n\
                 server.socket = \"{}\"\n\
                 {extra_config}\n",
                valkey.redis_url(),
                socket.display()
            ),
        )
        .expect("write config");

        let child = Command::new(env!("CARGO_BIN_EXE_postfix-ratelimitd"))
            .arg("--config")
            .arg(&config_path)
            .envs(env.iter().copied())
            .spawn()
            .expect("spawn daemon");

        let deadline = Instant::now() + READY_TIMEOUT;
        while !socket.exists() {
            assert!(Instant::now() < deadline, "daemon did not create its socket in time");
            std::thread::sleep(POLL_INTERVAL);
        }

        Daemon { child, socket, _dir: dir }
    }

    /// Sends one raw policy request (not necessarily well-formed) and returns
    /// the response, up to and including its blank-line terminator. Reads
    /// exactly one response rather than to EOF, since the daemon (correctly)
    /// keeps the connection open for further requests rather than closing it.
    fn raw_request(&self, request: &str) -> String {
        let stream = UnixStream::connect(&self.socket).expect("connect to daemon");
        (&stream).write_all(request.as_bytes()).expect("write request");

        let mut reader = BufReader::new(&stream);
        let mut response = String::new();
        loop {
            let mut line = String::new();
            let read = reader.read_line(&mut line).expect("read response line");
            assert!(read > 0, "daemon closed the connection before sending a full response");
            response.push_str(&line);
            if line == "\n" || line == "\r\n" {
                return response;
            }
        }
    }

    /// Sends one well-formed `protocol_state=DATA` policy request.
    fn request(&self, sasl_username: &str, recipient_count: u32) -> String {
        self.raw_request(&format!(
            "sasl_username={sasl_username}\nrecipient_count={recipient_count}\nprotocol_state=DATA\n\n"
        ))
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn successful_check_writes_a_real_key() {
    let valkey = ValkeyInstance::start_unix();
    let daemon = Daemon::start(
        &valkey,
        "redis.key_prefix = \"rl:\"\n\
         [[limits]]\n\
         type = \"default\"\n\
         windows = [ { count = 50, duration = \"1h\" } ]\n",
    );

    let response = daemon.request("alice", 3);
    assert_eq!(response, format!("action={ACTION_DUNNO}\n\n"));

    let keys = valkey.keys("rl:alice:*");
    assert_eq!(keys.len(), 1, "expected exactly one key for the one configured window");
    let mut connection = valkey.connection();
    let fields: Vec<(String, String)> = redis::cmd("HGETALL").arg(&keys[0]).query(&mut connection).expect("hgetall");
    assert_eq!(fields.len(), 1, "expected exactly one recorded bucket");
    assert_eq!(fields[0].1, "3", "bucket value should be the recipient count");
}

#[test]
fn wrong_protocol_state_defers_without_checking() {
    let valkey = ValkeyInstance::start_unix();
    let daemon = Daemon::start(
        &valkey,
        "redis.key_prefix = \"rl:\"\n\
         [[limits]]\n\
         type = \"default\"\n\
         windows = [ { count = 50, duration = \"1h\" } ]\n",
    );

    // RCPT-stage requests are a sign this is wired to the wrong Postfix restriction
    // class - deferred rather than checked, since recipient_count wouldn't yet
    // be the message's final total.
    let response = daemon.raw_request("sasl_username=alice\nrecipient_count=3\nprotocol_state=RCPT\n\n");
    assert_eq!(response, format!("action={ACTION_MISCONFIGURED}\n\n"));

    // Never reached the rate-limit check at all, so nothing should be recorded -
    // under any key, not just the one this window's own bucket size would use.
    assert!(valkey.keys("rl:alice:*").is_empty(), "a misconfigured-protocol-state request must not be recorded");
}

#[test]
fn missing_recipient_count_defers_without_checking() {
    let valkey = ValkeyInstance::start_unix();
    let daemon = Daemon::start(
        &valkey,
        "redis.key_prefix = \"rl:\"\n\
         [[limits]]\n\
         type = \"default\"\n\
         windows = [ { count = 50, duration = \"1h\" } ]\n",
    );

    // Same root cause as a wrong protocol_state - only smtpd_data_restrictions
    // populates recipient_count.
    let response = daemon.raw_request("sasl_username=alice\nprotocol_state=DATA\n\n");
    assert_eq!(response, format!("action={ACTION_MISCONFIGURED}\n\n"));

    assert!(valkey.keys("rl:alice:*").is_empty(), "a misconfigured request must not be recorded");
}

#[test]
fn unauthenticated_request_permitted_by_default() {
    let valkey = ValkeyInstance::start_unix();
    let daemon = Daemon::start(
        &valkey,
        "redis.key_prefix = \"rl:\"\n\
         [[limits]]\n\
         type = \"default\"\n\
         windows = [ { count = 50, duration = \"1h\" } ]\n",
    );

    // No sasl_username at all - nothing to rate-limit against.
    let response = daemon.raw_request("recipient_count=3\nprotocol_state=DATA\n\n");
    assert_eq!(response, format!("action={ACTION_DUNNO}\n\n"));
}

#[test]
fn unauthenticated_request_still_permitted_with_warning_silenced() {
    let valkey = ValkeyInstance::start_unix();
    let daemon = Daemon::start(
        &valkey,
        "redis.key_prefix = \"rl:\"\n\
         server.warn_on_unauthenticated = false\n\
         [[limits]]\n\
         type = \"default\"\n\
         windows = [ { count = 50, duration = \"1h\" } ]\n",
    );

    // warn_on_unauthenticated only silences the log line - it's still always
    // permitted, since there's no identity to rate-limit against either way.
    let response = daemon.raw_request("recipient_count=3\nprotocol_state=DATA\n\n");
    assert_eq!(response, format!("action={ACTION_DUNNO}\n\n"));
}

#[test]
fn redis_error_defers_by_default() {
    let valkey = ValkeyInstance::start_unix();
    let daemon = Daemon::start(
        &valkey,
        "[[limits]]\n\
         type = \"default\"\n\
         windows = [ { count = 50, duration = \"1h\" } ]\n",
    );

    // Establish the daemon's connection first, then take the whole backend away.
    daemon.request("alice", 1);
    drop(valkey);

    let response = daemon.request("alice", 1);
    assert_eq!(response, format!("action={ACTION_SERVICE_UNAVAILABLE}\n\n"));
}

#[test]
fn redis_error_permits_when_configured() {
    let valkey = ValkeyInstance::start_unix();
    let daemon = Daemon::start(
        &valkey,
        "server.on_redis_error = \"permit\"\n\
         [[limits]]\n\
         type = \"default\"\n\
         windows = [ { count = 50, duration = \"1h\" } ]\n",
    );

    daemon.request("alice", 1);
    drop(valkey);

    let response = daemon.request("alice", 1);
    assert_eq!(response, format!("action={ACTION_DUNNO}\n\n"));
}

#[test]
fn successful_check_over_tcp() {
    let valkey = ValkeyInstance::start_tcp();
    let daemon = Daemon::start(
        &valkey,
        "redis.key_prefix = \"rl:\"\n\
         [[limits]]\n\
         type = \"default\"\n\
         windows = [ { count = 50, duration = \"1h\" } ]\n",
    );

    let response = daemon.request("alice", 3);
    assert_eq!(response, format!("action={ACTION_DUNNO}\n\n"));

    let keys = valkey.keys("rl:alice:*");
    assert_eq!(keys.len(), 1, "expected exactly one key for the one configured window");
    let mut connection = valkey.connection();
    let fields: Vec<(String, String)> = redis::cmd("HGETALL").arg(&keys[0]).query(&mut connection).expect("hgetall");
    assert_eq!(fields.len(), 1, "expected exactly one recorded bucket");
}

#[test]
fn rate_limit_exceeded_defers_and_does_not_record() {
    let valkey = ValkeyInstance::start_unix();
    let daemon = Daemon::start(
        &valkey,
        "redis.key_prefix = \"rl:\"\n\
         [[limits]]\n\
         type = \"default\"\n\
         windows = [ { count = 2, duration = \"1h\" } ]\n",
    );

    // Exactly at the limit: accepted and recorded.
    let response = daemon.request("alice", 2);
    assert_eq!(response, format!("action={ACTION_DUNNO}\n\n"));

    // One more recipient would push the window's total over its limit: rejected.
    let response = daemon.request("alice", 1);
    assert_eq!(response, format!("action={ACTION_RATE_LIMITED}\n\n"));

    // The rejected message must not have been recorded alongside the accepted one.
    let keys = valkey.keys("rl:alice:*");
    assert_eq!(keys.len(), 1, "expected exactly one key for the one configured window");
    let mut connection = valkey.connection();
    let fields: Vec<(String, String)> = redis::cmd("HGETALL").arg(&keys[0]).query(&mut connection).expect("hgetall");
    assert_eq!(fields.len(), 1, "rejected message must not be recorded");
    assert_eq!(fields[0].1, "2", "recorded bucket should still reflect only the accepted message");
}

#[test]
fn exceeding_either_window_defers_and_accepted_records_in_both() {
    let valkey = ValkeyInstance::start_unix();
    let daemon = Daemon::start(
        &valkey,
        "redis.key_prefix = \"rl:\"\n\
         [[limits]]\n\
         type = \"default\"\n\
         windows = [ { count = 100, duration = \"1h\" }, { count = 2, duration = \"1d\" } ]\n",
    );

    // Fits the generous hourly window but exceeds the tight daily one: still
    // rejected.
    let response = daemon.request("alice", 3);
    assert_eq!(response, format!("action={ACTION_RATE_LIMITED}\n\n"));
    assert!(valkey.keys("rl:alice:*").is_empty(), "rejected message must not be recorded in any window");

    // Fits both windows: accepted and recorded in both. The 1h and 1d windows
    // land on different bucket sizes, so each gets its own key - discovered
    // rather than assumed, so a change to that computation makes this fail
    // loudly instead of silently checking the wrong keys.
    let response = daemon.request("alice", 2);
    assert_eq!(response, format!("action={ACTION_DUNNO}\n\n"));

    let keys = valkey.keys("rl:alice:*");
    assert_eq!(keys.len(), 2, "the hourly and daily windows should each get their own key");
    let mut connection = valkey.connection();
    for key in &keys {
        let fields: Vec<(String, String)> = redis::cmd("HGETALL").arg(key).query(&mut connection).expect("hgetall");
        assert_eq!(fields.len(), 1, "accepted message should be recorded once in {key}");
    }
}

#[test]
fn expired_entries_stop_counting_against_the_limit() {
    let valkey = ValkeyInstance::start_unix();
    let daemon = Daemon::start(
        &valkey,
        "redis.key_prefix = \"rl:\"\n\
         [[limits]]\n\
         type = \"default\"\n\
         windows = [ { count = 1, duration = \"60s\" } ]\n",
    );

    // Discover the real key this window's config computes, via a throwaway
    // username so as not to spend alice's own count-1 limit finding out -
    // rather than assuming a bucket size, so a change to that computation
    // makes this test fail loudly instead of silently seeding (and later
    // checking) a key the daemon never touches.
    let probe_response = daemon.request("probe", 1);
    assert_eq!(probe_response, format!("action={ACTION_DUNNO}\n\n"), "probe message should be accepted");
    let probe_keys = valkey.keys("rl:probe:*");
    assert_eq!(probe_keys.len(), 1, "expected exactly one key for the probe window");
    let bucket_size: u64 = probe_keys[0]
        .rsplit(':')
        .next()
        .expect("key has a bucket-size suffix")
        .parse()
        .expect("bucket size is numeric");
    let key = format!("rl:alice:{bucket_size}");

    // Seed a bucket far outside the window's lookback, as if a message had
    // been recorded and then aged out - real time never needs to pass for
    // that to happen.
    let stale_bucket = valkey.current_bucket(bucket_size) - 1000;
    let mut connection = valkey.connection();
    let _: () =
        redis::cmd("HSET").arg(&key).arg(stale_bucket).arg(1).query(&mut connection).expect("seed stale bucket");

    // The stale entry must not count against the limit.
    let response = daemon.request("alice", 1);
    assert_eq!(response, format!("action={ACTION_DUNNO}\n\n"));

    // It must also have been pruned once touched, leaving only the new entry.
    let fields: Vec<String> = redis::cmd("HKEYS").arg(&key).query(&mut connection).expect("hkeys");
    assert_eq!(fields.len(), 1, "the expired entry should have been pruned, leaving only the new one");
    assert_ne!(fields[0], stale_bucket.to_string(), "the surviving entry should be the new bucket, not the stale one");
}

#[test]
fn a_week_long_window_expires_via_the_real_check_and_record_logic() {
    let valkey = ValkeyInstance::start_unix();
    let config = "redis.key_prefix = \"rl:\"\n\
                  [[limits]]\n\
                  type = \"default\"\n\
                  windows = [ { count = 1, duration = \"7d\" } ]\n";
    let base_now = SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock").as_secs();

    // POSTFIX_RATELIMITD_FAKE_NOW fixes what the real check_and_record.lua sees
    // as "now", so real messages can be recorded and aged out across a
    // week-long window without waiting a week - the daemon holds no state of
    // its own between requests, so restarting it with a different fake time is
    // equivalent to time passing for a real, long-lived daemon.
    let now = base_now.to_string();
    let daemon = Daemon::start_with_env(&valkey, config, &[("POSTFIX_RATELIMITD_FAKE_NOW", now.as_str())]);
    let response = daemon.request("alice", 1);
    assert_eq!(response, format!("action={ACTION_DUNNO}\n\n"), "the first message should fit in an empty window");
    drop(daemon);

    // Immediately after, still within the window: a second message exceeds the
    // count-1 limit.
    let daemon = Daemon::start_with_env(&valkey, config, &[("POSTFIX_RATELIMITD_FAKE_NOW", now.as_str())]);
    let response = daemon.request("alice", 1);
    assert_eq!(
        response,
        format!("action={ACTION_RATE_LIMITED}\n\n"),
        "a second message in the same instant should be rejected"
    );
    drop(daemon);

    // 8 days later, past the 7d window: the first message has aged out, so a
    // new one fits again.
    let eight_days_later = (base_now + 8 * 24 * 60 * 60).to_string();
    let daemon = Daemon::start_with_env(&valkey, config, &[("POSTFIX_RATELIMITD_FAKE_NOW", eight_days_later.as_str())]);
    let response = daemon.request("alice", 1);
    assert_eq!(
        response,
        format!("action={ACTION_DUNNO}\n\n"),
        "the week-old message should have aged out of the 7d window"
    );
}

#[test]
fn window_lifecycle_at_the_minimum_duration_extreme() {
    let valkey = ValkeyInstance::start_unix();
    // 60s is MIN_WINDOW_DURATION; it lands on a 2s bucket size with a span_secs
    // of exactly 60s (see
    // config::tests::bucket_size_hits_target_count_at_min_window_duration).
    let config = "redis.key_prefix = \"rl:\"\n\
                  [[limits]]\n\
                  type = \"default\"\n\
                  windows = [ { count = 1, duration = \"60s\" } ]\n";
    let base_now = SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock").as_secs();

    let now = base_now.to_string();
    let daemon = Daemon::start_with_env(&valkey, config, &[("POSTFIX_RATELIMITD_FAKE_NOW", now.as_str())]);
    let response = daemon.request("alice", 1);
    assert_eq!(response, format!("action={ACTION_DUNNO}\n\n"), "the first message should fit in an empty window");
    drop(daemon);

    let daemon = Daemon::start_with_env(&valkey, config, &[("POSTFIX_RATELIMITD_FAKE_NOW", now.as_str())]);
    let response = daemon.request("alice", 1);
    assert_eq!(
        response,
        format!("action={ACTION_RATE_LIMITED}\n\n"),
        "a second message in the same instant should be rejected"
    );
    drop(daemon);

    let later = (base_now + 120).to_string();
    let daemon = Daemon::start_with_env(&valkey, config, &[("POSTFIX_RATELIMITD_FAKE_NOW", later.as_str())]);
    let response = daemon.request("alice", 1);
    assert_eq!(response, format!("action={ACTION_DUNNO}\n\n"), "the message should have aged out of the 60s window");
}

#[test]
fn window_lifecycle_at_the_maximum_duration_extreme() {
    let valkey = ValkeyInstance::start_unix();
    // 31d is MAX_WINDOW_DURATION; it clamps to MAX_BUCKET_SIZE (65536s), giving
    // a span_secs of 2,686,976s (~31.09d, not the nominal 2,678,400s) - see
    // config::tests::bucket_size_is_clamped_to_max_at_max_window_duration.
    let config = "redis.key_prefix = \"rl:\"\n\
                  [[limits]]\n\
                  type = \"default\"\n\
                  windows = [ { count = 1, duration = \"31d\" } ]\n";
    let base_now = SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock").as_secs();

    let now = base_now.to_string();
    let daemon = Daemon::start_with_env(&valkey, config, &[("POSTFIX_RATELIMITD_FAKE_NOW", now.as_str())]);
    let response = daemon.request("alice", 1);
    assert_eq!(response, format!("action={ACTION_DUNNO}\n\n"), "the first message should fit in an empty window");
    drop(daemon);

    let daemon = Daemon::start_with_env(&valkey, config, &[("POSTFIX_RATELIMITD_FAKE_NOW", now.as_str())]);
    let response = daemon.request("alice", 1);
    assert_eq!(
        response,
        format!("action={ACTION_RATE_LIMITED}\n\n"),
        "a second message in the same instant should be rejected"
    );
    drop(daemon);

    // Past the actual ~31.09d span, not just the nominal 31 days.
    let later = (base_now + 33 * 24 * 60 * 60).to_string();
    let daemon = Daemon::start_with_env(&valkey, config, &[("POSTFIX_RATELIMITD_FAKE_NOW", later.as_str())]);
    let response = daemon.request("alice", 1);
    assert_eq!(response, format!("action={ACTION_DUNNO}\n\n"), "the message should have aged out of the 31d window");
}

#[test]
fn a_shorter_window_stops_counting_before_its_shared_key_is_pruned() {
    let valkey = ValkeyInstance::start_unix();
    // A 16d and a 31d window both clamp to MAX_BUCKET_SIZE (65536s) and so
    // share one Redis key, but their own spans differ (~16.68d vs ~31.09d) -
    // the shared key's retention (and prune cutoff) is the longer of the two,
    // so an entry can correctly stop counting against the 16d window's own
    // limit long before it's actually deleted.
    let config = "redis.key_prefix = \"rl:\"\n\
                  [[limits]]\n\
                  type = \"default\"\n\
                  windows = [ { count = 1, duration = \"16d\" }, { count = 5, duration = \"31d\" } ]\n";
    let base_now = SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock").as_secs();

    let now = base_now.to_string();
    let daemon = Daemon::start_with_env(&valkey, config, &[("POSTFIX_RATELIMITD_FAKE_NOW", now.as_str())]);
    let response = daemon.request("alice", 1);
    assert_eq!(response, format!("action={ACTION_DUNNO}\n\n"), "the first message should fit both empty windows");
    drop(daemon);

    // 20 days later: past the 16d window's own ~16.68d span, but well before
    // the shared key's ~31.09d retention. If the 16d window incorrectly used
    // the shared key's longer retention as its own cutoff instead of its own
    // span, this message would push its count-1 limit to 2 and be rejected.
    let twenty_days_later = (base_now + 20 * 24 * 60 * 60).to_string();
    let daemon =
        Daemon::start_with_env(&valkey, config, &[("POSTFIX_RATELIMITD_FAKE_NOW", twenty_days_later.as_str())]);
    let response = daemon.request("alice", 1);
    assert_eq!(
        response,
        format!("action={ACTION_DUNNO}\n\n"),
        "the 16d window should have already stopped counting the 20-day-old message"
    );

    // Both windows should indeed share one key - the premise this test's name
    // rests on - discovered rather than assumed, so a change to the bucket-size
    // computation makes this fail loudly instead of silently checking a key
    // the daemon never touches.
    let keys = valkey.keys("rl:alice:*");
    assert_eq!(keys.len(), 1, "the 16d and 31d windows should share one key");

    // The 20-day-old entry must still be physically present, though - it's
    // excluded from the 16d window's own sum, not yet pruned from the shared
    // key, since the key's retention is the 31d window's longer span.
    let mut connection = valkey.connection();
    let fields: Vec<String> = redis::cmd("HKEYS").arg(&keys[0]).query(&mut connection).expect("hkeys");
    assert_eq!(fields.len(), 2, "the 20-day-old entry should still be present (not yet pruned), alongside the new one");
}

#[test]
fn multi_window_rule_ages_out_each_window_independently() {
    let valkey = ValkeyInstance::start_unix();
    // The README's own example rule: a tight hourly cap and a much looser
    // daily one. 1h and 1d land on different bucket sizes, so - unlike
    // a_shorter_window_stops_counting_before_its_shared_key_is_pruned's shared
    // key - each window keeps its own key and ages out fully independently.
    // The daily cap (21) is deliberately tight, not generous like the hourly
    // one - see the last stage below, which depends on it.
    let config = "redis.key_prefix = \"rl:\"\n\
                  [[limits]]\n\
                  type = \"default\"\n\
                  windows = [ { count = 20, duration = \"1h\" }, { count = 21, duration = \"1d\" } ]\n";
    let base_now = SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock").as_secs();

    // Fills the hourly cap exactly, and puts the daily one at 20/21.
    let now = base_now.to_string();
    let daemon = Daemon::start_with_env(&valkey, config, &[("POSTFIX_RATELIMITD_FAKE_NOW", now.as_str())]);
    let response = daemon.request("alice", 20);
    assert_eq!(response, format!("action={ACTION_DUNNO}\n\n"), "first message should fit both empty windows");

    let response = daemon.request("alice", 1);
    assert_eq!(response, format!("action={ACTION_RATE_LIMITED}\n\n"), "the hourly cap should already be full");
    drop(daemon);

    // 2 hours later: past the hourly window's own span (~62 minutes), but
    // nowhere near the daily window's (~25 hours) - the hourly window should
    // have reset while the daily total (still counting the 2-hour-old
    // message) is exactly full at 21/21.
    let two_hours_later = (base_now + 2 * 60 * 60).to_string();
    let daemon = Daemon::start_with_env(&valkey, config, &[("POSTFIX_RATELIMITD_FAKE_NOW", two_hours_later.as_str())]);
    let response = daemon.request("alice", 1);
    assert_eq!(
        response,
        format!("action={ACTION_DUNNO}\n\n"),
        "the hourly window should have reset, even though the daily one hasn't"
    );

    // One more message, still at the same instant: the hourly window (now at
    // 1/20) has plenty of room, but the daily one is exactly full. This only
    // rejects if the 2-hour-old message is still correctly counted against
    // the daily window's own (much longer) span - if a bug used the hourly
    // window's shorter span for both (a real mistake this guards against:
    // reusing one window's cutoff for another), the daily window would
    // wrongly see only the last two messages and accept this one too.
    let daemon = Daemon::start_with_env(&valkey, config, &[("POSTFIX_RATELIMITD_FAKE_NOW", two_hours_later.as_str())]);
    let response = daemon.request("alice", 1);
    assert_eq!(response, format!("action={ACTION_RATE_LIMITED}\n\n"), "the daily cap should already be exactly full");
}

#[test]
fn overcount_bound_holds_against_real_recorded_data() {
    let valkey = ValkeyInstance::start_unix();
    // What matters here is only the documented bound itself
    // (BUCKET_TARGET_COUNT), not this duration's specific resulting bucket
    // size or span - computed from the real constant so this can't silently
    // drift out of sync with it, unlike asserting a specific span value would.
    let duration_secs = 3600u64;
    let config = "redis.key_prefix = \"rl:\"\n\
                  [[limits]]\n\
                  type = \"default\"\n\
                  windows = [ { count = 1, duration = \"3600s\" } ]\n";
    let base_now = SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock").as_secs();

    let now = base_now.to_string();
    let daemon = Daemon::start_with_env(&valkey, config, &[("POSTFIX_RATELIMITD_FAKE_NOW", now.as_str())]);
    let response = daemon.request("alice", 1);
    assert_eq!(response, format!("action={ACTION_DUNNO}\n\n"), "first message should fit an empty window");
    drop(daemon);

    // Exactly at the window's true nominal duration: the floor guarantee (a
    // message is never excluded before its window has actually elapsed)
    // means it must still count here, however the bucketing scheme rounds.
    let at_true_duration = (base_now + duration_secs).to_string();
    let daemon = Daemon::start_with_env(&valkey, config, &[("POSTFIX_RATELIMITD_FAKE_NOW", at_true_duration.as_str())]);
    let response = daemon.request("alice", 1);
    assert_eq!(
        response,
        format!("action={ACTION_RATE_LIMITED}\n\n"),
        "a message must still count exactly at its window's true duration"
    );
    drop(daemon);

    // Just past the worst-case overcount the design permits (duration +
    // duration/BUCKET_TARGET_COUNT): the ceiling guarantee means it's
    // excluded by here, whatever this duration's actual span happens to be.
    let worst_case_overcount = duration_secs / BUCKET_TARGET_COUNT;
    let past_worst_case = (base_now + duration_secs + worst_case_overcount + 1).to_string();
    let daemon = Daemon::start_with_env(&valkey, config, &[("POSTFIX_RATELIMITD_FAKE_NOW", past_worst_case.as_str())]);
    let response = daemon.request("alice", 1);
    assert_eq!(
        response,
        format!("action={ACTION_DUNNO}\n\n"),
        "a message must be excluded once past the documented worst-case overcount"
    );
}

#[test]
fn tls_connection_to_valkey_with_custom_ca() {
    let valkey = ValkeyInstance::start_tls();
    let ca_cert = valkey.tls_ca_cert().to_str().expect("fixture CA path is valid UTF-8");
    let daemon = Daemon::start_with_env(
        &valkey,
        "redis.key_prefix = \"rl:\"\n\
         [[limits]]\n\
         type = \"default\"\n\
         windows = [ { count = 50, duration = \"1h\" } ]\n",
        &[("SSL_CERT_FILE", ca_cert)],
    );

    let response = daemon.request("alice", 3);
    assert_eq!(response, format!("action={ACTION_DUNNO}\n\n"));

    // Confirms the check actually went through the TLS-only server, not a fallback.
    let keys = valkey.keys("rl:alice:*");
    assert_eq!(keys.len(), 1, "expected exactly one key for the one configured window");
    let mut connection = valkey.connection();
    let fields: Vec<(String, String)> = redis::cmd("HGETALL").arg(&keys[0]).query(&mut connection).expect("hgetall");
    assert_eq!(fields.len(), 1, "expected exactly one recorded bucket");
}
