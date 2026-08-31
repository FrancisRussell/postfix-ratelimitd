use std::borrow::Cow;
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

/// Identifies a key as a per-user rate-limit bucket hash, distinguishing it
/// from any other kind of key that might one day share `key_prefix`.
const BUCKET_KEY_TYPE: &str = "bucket";

/// This key type's schema version - independent of any other key type's, so
/// introducing or revising one doesn't force bumping (and so orphaning) keys
/// of another. Bump this if a future change to `bucket_key`'s format or the
/// meaning of a bucket hash's fields could otherwise make old-format data
/// misread as valid under new code; a key-shape change alone doesn't need
/// this, since it already can't collide with the shape it replaces.
const BUCKET_SCHEMA_VERSION: &str = "v1";

/// Escapes `\` and `:` in `sasl_username` so it can't be mistaken for
/// anything else once joined into a bucket key - see `bucket_key`. Borrows
/// the input unchanged when nothing needs escaping, which is the common case
/// for real usernames, rather than always allocating a new `String`.
fn escape_username(sasl_username: &str) -> Cow<'_, str> {
    if sasl_username.contains(['\\', ':']) {
        Cow::Owned(sasl_username.replace('\\', "\\\\").replace(':', "\\:"))
    } else {
        Cow::Borrowed(sasl_username)
    }
}

/// The Redis key for one `sasl_username`'s bucket at `bucket_size` - the only
/// place a bucket key gets built, so escaping `sasl_username` here is enough
/// to guarantee it everywhere.
///
/// `bucket_size` is always plain decimal digits, so escaping `\` and `:` in
/// `sasl_username` (backslash-escaping the escape character itself, then the
/// separator) guarantees two different `(sasl_username, bucket_size)` pairs
/// never produce the same key: the last unescaped `:` unambiguously marks
/// where `bucket_size` starts. Without this, `sasl_username` "alice:64"
/// would collide with username "alice" at `bucket_size` 64.
fn bucket_key(key_prefix: &str, sasl_username: &str, bucket_size: u64) -> String {
    let escaped = escape_username(sasl_username);
    format!("{key_prefix}:{BUCKET_KEY_TYPE}:{BUCKET_SCHEMA_VERSION}:{escaped}:{bucket_size}")
}

/// Commands `check_and_record.lua` and `Script::invoke_async` depend on:
/// `EVALSHA` and `SCRIPT` (the latter for `SCRIPT LOAD`, on a cache miss -
/// `redis`'s `Script` never falls back to plain `EVAL`), and the script's own
/// `HGETALL`/`HINCRBY`/`HDEL`/`EXPIRE`/`TIME` calls.
const REQUIRED_COMMANDS: &[&str] = &["EVALSHA", "SCRIPT", "HGETALL", "HINCRBY", "HDEL", "EXPIRE", "TIME"];

/// Confirms the connected server recognizes every command in `commands`, so
/// an incompatible server is refused loudly here - once per connection, at
/// startup or reload (see `Limiter::new`, which passes [`REQUIRED_COMMANDS`])
/// - rather than only surfacing as a script error on the first real check.
pub async fn check_command_support(connection: &mut ConnectionManager, commands: &[&str]) -> redis::RedisResult<()> {
    let info: Vec<redis::Value> = redis::cmd("COMMAND").arg("INFO").arg(commands).query_async(connection).await?;
    let missing: Vec<&str> = commands
        .iter()
        .zip(&info)
        .filter(|(_, info)| matches!(info, redis::Value::Nil))
        .map(|(&name, _)| name)
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err((redis::ErrorKind::Client, "server is missing required commands", missing.join(", ")).into())
    }
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
        let mut connection_manager = client.get_connection_manager_with_config(manager_config).await?;
        check_command_support(&mut connection_manager, REQUIRED_COMMANDS).await?;
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
    #[allow(clippy::missing_panics_doc)] // the only panic is an internal invariant, not a caller-facing condition
    pub async fn check(
        &self, sasl_username: &str, recipient_count: u32, plan: &CheckPlan, now_override: Option<u64>,
    ) -> redis::RedisResult<bool> {
        let mut connection = self.connection_manager.clone();
        let mut invocation = self.script.prepare_invoke();

        for &bucket_size in &plan.bucket_sizes {
            invocation.key(bucket_key(&self.key_prefix, sasl_username, bucket_size));
        }

        let request = CheckRequest { recipient_count, now_override, plan: plan.fields() };
        let request =
            serde_json::to_string(&request).expect("CheckRequest contains no types that can fail to serialize");
        invocation.arg(request);

        let allowed: i64 = invocation.invoke_async(&mut connection).await?;
        Ok(allowed == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_username_borrows_when_nothing_needs_escaping() {
        assert!(matches!(escape_username("alice"), Cow::Borrowed(_)));
    }

    #[test]
    fn escape_username_allocates_only_when_escaping_is_needed() {
        assert!(matches!(escape_username("alice:64"), Cow::Owned(_)));
        assert!(matches!(escape_username("alice\\"), Cow::Owned(_)));
    }

    #[test]
    fn bucket_key_does_not_collide_across_the_username_bucket_size_boundary() {
        // Without escaping, both would produce "prefix:bucket:v1:alice:64".
        let a = bucket_key("prefix", "alice:64", 1);
        let b = bucket_key("prefix", "alice", 64);
        assert_ne!(a, b);
    }

    #[test]
    fn bucket_key_does_not_collide_when_a_username_ends_in_a_backslash() {
        // Without escaping the escape character itself, both would produce
        // "prefix:bucket:v1:alice\:64".
        let a = bucket_key("prefix", "alice\\", 64);
        let b = bucket_key("prefix", "alice", 64);
        assert_ne!(a, b);
    }
}
