use std::borrow::Cow;
use std::time::Duration;

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::{Client, ConnectionInfo, Script};
use serde::Serialize;

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

/// One `check_and_record.lua` invocation's arguments, sent as a single JSON
/// value.
#[derive(Serialize)]
struct CheckRequest<'a> {
    recipient_count: u32,
    // Omitted entirely rather than sent as JSON `null` when absent since cjson
    // decodes a JSON `null` to the sentinel `cjson.null` which is truthy.
    #[serde(skip_serializing_if = "Option::is_none")]
    now_override: Option<u64>,
    plan: &'a CheckPlan,
}

/// Identifies a key as a per-user rate-limit bucket hash.
const BUCKET_KEY_TYPE: &str = "bucket";

/// The bucket schema version. This should be bumped if the format or interpretation
/// of the bucket data changes.
const BUCKET_SCHEMA_VERSION: &str = "v1";

/// The identity kind tagging every `sasl_username` bucketed by
/// `Limiter::check_sasl`.
const SASL_IDENTITY_KIND: &str = "sasl";

/// Escapes `\` and `:` in `value` so it can't be mistaken for anything else
/// once embedded in an `identity` string.
fn escape_identity_value(value: &str) -> Cow<'_, str> {
    if value.contains(['\\', ':']) {
        Cow::Owned(value.replace('\\', "\\\\").replace(':', "\\:"))
    } else {
        Cow::Borrowed(value)
    }
}

/// Formats `value` as a `bucket_key` identity, tagged with `kind` so a
/// different kind sharing the same literal `value` can't collide onto the
/// same key. `kind` must never itself contain `\` or `:`.
fn identity(kind: &str, value: &str) -> String {
    debug_assert!(!kind.contains(['\\', ':']), "identity kind {kind:?} must not contain '\\' or ':'");
    format!("{kind}:{}", escape_identity_value(value))
}

/// The Redis key for one `bucket_size` slice of `identity`'s recorded
/// counts. This is the only place a bucket key is assembled.
fn bucket_key(key_prefix: &str, identity: &str, bucket_size: u64) -> String {
    format!("{key_prefix}:{BUCKET_KEY_TYPE}:{BUCKET_SCHEMA_VERSION}:{identity}:{bucket_size}")
}

/// Commands `check_and_record.lua` and `Script::invoke_async` depend on:
/// `EVALSHA` and `SCRIPT` (the latter for `SCRIPT LOAD`, on a cache miss -
/// `redis`'s `Script` never falls back to plain `EVAL`), and the script's own
/// `HGETALL`/`HINCRBY`/`HDEL`/`EXPIRE`/`TIME` calls.
const REQUIRED_COMMANDS: &[&str] = &["EVALSHA", "SCRIPT", "HGETALL", "HINCRBY", "HDEL", "EXPIRE", "TIME"];

/// Confirms the connected server recognizes every command in `commands`.
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

/// Checks and records recipient counts against Valkey via `check_and_record.lua`.
#[derive(Debug, Clone)]
pub struct Limiter {
    connection_manager: ConnectionManager,
    key_prefix: String,
    script: Script,
}

impl Limiter {
    /// Builds a `Limiter` from an already-resolved connection info (db and password included).
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

    /// Records `recipient_count` only if every window in `plan` accepts it; returns whether it was allowed.
    ///
    /// Windows are aggregated into time buckets and windows whose durations land on the same bucket size share a key,
    /// so a message updates each distinct key once, however many windows reference it. `plan`'s bucket sizes and spans
    /// depend only on window durations, never on a request. `now_override` should only ever be `Some` from a request
    /// under the integration-tests feature.
    ///
    /// An unrestricted rule's plan has no bucket sizes at all and so returns `Ok(true)` immediately without touching
    /// Redis/Valkey.
    #[allow(clippy::missing_panics_doc)] // the only panic is an internal invariant, not a caller-facing condition
    pub async fn check_sasl(
        &self, sasl_username: &str, recipient_count: u32, plan: &CheckPlan, now_override: Option<u64>,
    ) -> redis::RedisResult<bool> {
        if plan.bucket_sizes.is_empty() {
            return Ok(true);
        }

        let mut connection = self.connection_manager.clone();
        let mut invocation = self.script.prepare_invoke();

        let sasl_identity = identity(SASL_IDENTITY_KIND, sasl_username);
        for &bucket_size in &plan.bucket_sizes {
            invocation.key(bucket_key(&self.key_prefix, &sasl_identity, bucket_size));
        }

        let request = CheckRequest { recipient_count, now_override, plan };
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
    fn escape_identity_value_borrows_when_nothing_needs_escaping() {
        assert!(matches!(escape_identity_value("alice"), Cow::Borrowed(_)));
    }

    #[test]
    fn escape_identity_value_allocates_only_when_escaping_is_needed() {
        assert!(matches!(escape_identity_value("alice:64"), Cow::Owned(_)));
        assert!(matches!(escape_identity_value("alice\\"), Cow::Owned(_)));
    }

    #[test]
    fn identity_distinguishes_kinds_sharing_the_same_value() {
        assert_ne!(identity("sasl", "alice"), identity("mail-from", "alice"));
    }

    #[test]
    fn bucket_key_does_not_collide_across_the_identity_bucket_size_boundary() {
        // Without escaping, both would produce "prefix:bucket:v1:sasl:alice:64".
        let a = bucket_key("prefix", &identity(SASL_IDENTITY_KIND, "alice:64"), 1);
        let b = bucket_key("prefix", &identity(SASL_IDENTITY_KIND, "alice"), 64);
        assert_ne!(a, b);
    }

    #[test]
    fn bucket_key_does_not_collide_when_a_username_ends_in_a_backslash() {
        // Without escaping the escape character itself, both would produce
        // "prefix:bucket:v1:sasl:alice\:64".
        let a = bucket_key("prefix", &identity(SASL_IDENTITY_KIND, "alice\\"), 64);
        let b = bucket_key("prefix", &identity(SASL_IDENTITY_KIND, "alice"), 64);
        assert_ne!(a, b);
    }
}
