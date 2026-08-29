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
use std::time::{Duration, Instant};

/// How long to wait for a spawned `valkey-server` or daemon to become ready.
const READY_TIMEOUT: Duration = Duration::from_secs(5);

/// How often to poll while waiting for readiness.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// How a [`ValkeyInstance`] can be reached.
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
}

impl Drop for ValkeyInstance {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A running daemon instance and its temp config/socket, cleaned up on drop.
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

    /// Sends one policy request and returns the response, up to and including
    /// its blank-line terminator. Reads exactly one response rather than to
    /// EOF, since the daemon (correctly) keeps the connection open for
    /// further requests rather than closing it.
    fn request(&self, sasl_username: &str, recipient_count: u32) -> String {
        let stream = UnixStream::connect(&self.socket).expect("connect to daemon");
        (&stream)
            .write_all(
                format!("sasl_username={sasl_username}\nrecipient_count={recipient_count}\nprotocol_state=DATA\n\n")
                    .as_bytes(),
            )
            .expect("write request");

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
    assert_eq!(response, "action=dunno\n\n");

    // A 1h window lands on a 128s bucket size (see `config::bucket_size`).
    let mut connection = valkey.connection();
    let fields: Vec<(String, String)> =
        redis::cmd("HGETALL").arg("rl:alice:128").query(&mut connection).expect("hgetall");
    assert_eq!(fields.len(), 1, "expected exactly one recorded bucket");
    assert_eq!(fields[0].1, "3", "bucket value should be the recipient count");
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
    assert_eq!(response, "action=defer_if_permit Service temporarily unavailable\n\n");
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
    assert_eq!(response, "action=dunno\n\n");
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
    assert_eq!(response, "action=dunno\n\n");

    let mut connection = valkey.connection();
    let fields: Vec<(String, String)> =
        redis::cmd("HGETALL").arg("rl:alice:128").query(&mut connection).expect("hgetall");
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
    assert_eq!(response, "action=dunno\n\n");

    // One more recipient would push the window's total over its limit: rejected.
    let response = daemon.request("alice", 1);
    assert_eq!(response, "action=defer_if_permit Recipient rate limit exceeded, retry later\n\n");

    // The rejected message must not have been recorded alongside the accepted one.
    let mut connection = valkey.connection();
    let fields: Vec<(String, String)> =
        redis::cmd("HGETALL").arg("rl:alice:128").query(&mut connection).expect("hgetall");
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
    assert_eq!(response, "action=defer_if_permit Recipient rate limit exceeded, retry later\n\n");

    // The 1h and 1d windows land on different bucket sizes (128s and 4096s
    // respectively, see `config::bucket_size`), so each has its own key.
    let mut connection = valkey.connection();
    let hourly: Vec<(String, String)> =
        redis::cmd("HGETALL").arg("rl:alice:128").query(&mut connection).expect("hgetall");
    let daily: Vec<(String, String)> =
        redis::cmd("HGETALL").arg("rl:alice:4096").query(&mut connection).expect("hgetall");
    assert!(hourly.is_empty(), "rejected message must not be recorded in any window");
    assert!(daily.is_empty(), "rejected message must not be recorded in any window");

    // Fits both windows: accepted and recorded in both.
    let response = daemon.request("alice", 2);
    assert_eq!(response, "action=dunno\n\n");

    let hourly: Vec<(String, String)> =
        redis::cmd("HGETALL").arg("rl:alice:128").query(&mut connection).expect("hgetall");
    let daily: Vec<(String, String)> =
        redis::cmd("HGETALL").arg("rl:alice:4096").query(&mut connection).expect("hgetall");
    assert_eq!(hourly.len(), 1, "accepted message should be recorded in the hourly window");
    assert_eq!(daily.len(), 1, "accepted message should be recorded in the daily window");
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

    // A 60s window lands on a 2s bucket size (see `config::bucket_size`). Seed a
    // bucket far outside the window's lookback, as if a message had been
    // recorded and then aged out - real time never needs to pass for that to
    // happen.
    let stale_bucket = valkey.current_bucket(2) - 1000;
    let mut connection = valkey.connection();
    let _: () = redis::cmd("HSET")
        .arg("rl:alice:2")
        .arg(stale_bucket)
        .arg(1)
        .query(&mut connection)
        .expect("seed stale bucket");

    // The stale entry must not count against the limit.
    let response = daemon.request("alice", 1);
    assert_eq!(response, "action=dunno\n\n");

    // It must also have been pruned once touched, leaving only the new entry.
    let fields: Vec<String> = redis::cmd("HKEYS").arg("rl:alice:2").query(&mut connection).expect("hkeys");
    assert_eq!(fields.len(), 1, "the expired entry should have been pruned, leaving only the new one");
    assert_ne!(fields[0], stale_bucket.to_string(), "the surviving entry should be the new bucket, not the stale one");
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
    assert_eq!(response, "action=dunno\n\n");

    // Confirms the check actually went through the TLS-only server, not a fallback.
    let mut connection = valkey.connection();
    let fields: Vec<(String, String)> =
        redis::cmd("HGETALL").arg("rl:alice:128").query(&mut connection).expect("hgetall");
    assert_eq!(fields.len(), 1, "expected exactly one recorded bucket");
}
