use std::time::Duration;

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::{Client, ConnectionInfo, Script};

use crate::config::CheckPlan;

const CHECK_AND_RECORD: &str = include_str!("../lua/check_and_record.lua");

/// Bounds a hung connection attempt, e.g. a network blackhole.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(3);

/// Bounds a hung reply from a connected-but-unresponsive server.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);

/// How many times to retry a failed connection, including the initial one -
/// `ConnectionManager` reuses this retry loop for its first connect, not just
/// for reconnecting later, so this also bounds how long a bad config takes to
/// fail.
const CONNECTION_RETRIES: usize = 3;

/// Caps the delay between connection retries; `ConnectionManagerConfig`'s own
/// default backoff can reach tens of seconds per attempt.
const CONNECTION_RETRY_MAX_DELAY: Duration = Duration::from_secs(1);

/// Test-only escape hatch: when set, a fixed unix timestamp `check` sends the
/// script as "now" instead of letting it call Valkey's own TIME - lets a test
/// exercise weeks- or months-long windows without real time passing. Not a
/// documented config option; never set outside tests.
const FAKE_NOW_ENV_VAR: &str = "POSTFIX_RATELIMITD_FAKE_NOW";

/// Checks and records recipient counts against Valkey via
/// `check_and_record.lua`.
#[derive(Clone)]
pub struct Limiter {
    connection_manager: ConnectionManager,
    key_prefix: String,
    script: Script,
    fake_now: Option<u64>,
}

impl Limiter {
    /// Builds a `Limiter` from an already-resolved connection info (db and
    /// password included).
    pub async fn new(connection_info: ConnectionInfo, key_prefix: String) -> redis::RedisResult<Limiter> {
        let client = Client::open(connection_info)?;
        let manager_config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(CONNECTION_TIMEOUT))
            .set_response_timeout(Some(RESPONSE_TIMEOUT))
            .set_number_of_retries(CONNECTION_RETRIES)
            .set_max_delay(CONNECTION_RETRY_MAX_DELAY);
        let connection_manager = client.get_connection_manager_with_config(manager_config).await?;
        let fake_now = std::env::var(FAKE_NOW_ENV_VAR).ok().and_then(|value| value.parse().ok());
        Ok(Limiter { connection_manager, key_prefix, script: Script::new(CHECK_AND_RECORD), fake_now })
    }

    /// Records `recipient_count` only if every window in `plan` accepts it;
    /// returns whether it was allowed.
    ///
    /// Windows are aggregated into time buckets (see `check_and_record.lua`),
    /// and windows whose durations land on the same bucket size share a key,
    /// so a message updates each distinct key once, however many windows
    /// reference it. `plan` is precomputed once per config load/reload (see
    /// `config::CheckPlan`), since it depends only on window durations, never
    /// on a request. It's passed to the script as JSON rather than flattened
    /// into positional arguments, so the two sides can't silently drift out
    /// of step on argument order or count.
    pub async fn check(&self, sasl_username: &str, recipient_count: u32, plan: &CheckPlan) -> redis::RedisResult<bool> {
        let mut connection = self.connection_manager.clone();
        let mut invocation = self.script.prepare_invoke();

        for &bucket_size in &plan.bucket_sizes {
            invocation.key(format!("{}{}:{}", self.key_prefix, sasl_username, bucket_size));
        }

        invocation.arg(recipient_count).arg(plan.json());
        if let Some(fake_now) = self.fake_now {
            invocation.arg(fake_now);
        }

        let allowed: i64 = invocation.invoke_async(&mut connection).await?;
        Ok(allowed == 1)
    }
}
