use std::time::Duration;

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::{Client, ConnectionInfo, Script};
use serde::Serialize;

use crate::config::{CheckPlan, CheckPlanFields};

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

/// One `check_and_record.lua` invocation's arguments, sent as a single JSON
/// value rather than flattened into positional arguments, so the two sides
/// can't silently drift out of step on argument order or count.
#[derive(Serialize)]
struct CheckRequest<'a> {
    recipient_count: u32,
    // Omitted entirely rather than sent as JSON `null` when absent: cjson
    // decodes a JSON `null` to the sentinel `cjson.null`, not Lua's `nil` -
    // which is truthy, so the script's `if request.now_override then` check would
    // misfire on every request if this were serialized as `null` instead of
    // left out. Only ever `Some` when the caller got it from
    // `Request::now_override`, which doesn't exist outside the integration-tests
    // feature - see there for why this doesn't need its own gate here too.
    #[serde(skip_serializing_if = "Option::is_none")]
    now_override: Option<u64>,
    plan: CheckPlanFields<'a>,
}

/// Checks and records recipient counts against Valkey via
/// `check_and_record.lua`.
#[derive(Clone)]
pub struct Limiter {
    connection_manager: ConnectionManager,
    key_prefix: String,
    script: Script,
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
        Ok(Limiter { connection_manager, key_prefix, script: Script::new(CHECK_AND_RECORD) })
    }

    /// Records `recipient_count` only if every window in `plan` accepts it;
    /// returns whether it was allowed.
    ///
    /// Windows are aggregated into time buckets (see `check_and_record.lua`),
    /// and windows whose durations land on the same bucket size share a key,
    /// so a message updates each distinct key once, however many windows
    /// reference it. `plan`'s bucket sizes and spans depend only on window
    /// durations, never on a request, but re-serializing them alongside
    /// `recipient_count` on every check is cheap enough not to be worth
    /// caching separately. `now_override` should only ever be `Some` from a
    /// request under the integration-tests feature - see
    /// `Request::now_override`.
    pub async fn check(
        &self, sasl_username: &str, recipient_count: u32, plan: &CheckPlan, now_override: Option<u64>,
    ) -> redis::RedisResult<bool> {
        let mut connection = self.connection_manager.clone();
        let mut invocation = self.script.prepare_invoke();

        for &bucket_size in &plan.bucket_sizes {
            invocation.key(format!("{}{}:{}", self.key_prefix, sasl_username, bucket_size));
        }

        let request = CheckRequest { recipient_count, now_override, plan: plan.fields() };
        let request =
            serde_json::to_string(&request).expect("CheckRequest contains no types that can fail to serialize");
        invocation.arg(request);

        let allowed: i64 = invocation.invoke_async(&mut connection).await?;
        Ok(allowed == 1)
    }
}
