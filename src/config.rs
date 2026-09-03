use std::path::{Path, PathBuf};
use std::time::Duration;

use redis::{ConnectionInfo, IntoConnectionInfo};
use regex_lite::Regex;
use serde::{Deserialize, Serialize};

/// One recipient-count cap over a sliding time window.
#[derive(Debug, Clone, Deserialize)]
pub struct Window {
    pub count: u32,
    #[serde(with = "humantime_serde")]
    pub duration: Duration,
}

/// A `sasl` entry as written in the config file, before its regex is
/// compiled. `windows` and `unrestricted` are both optional and independent
/// at this level - omitting either leaves it `None`, distinct from writing
/// it out as empty or `false`. `build_plan` treats every combination other
/// than "windows only" or "unrestricted = true only" as an error - see its
/// own doc comment for why `unrestricted = false` is rejected rather than
/// accepted as a no-op.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum RawSaslLimitRule {
    Username {
        username: String,
        #[serde(default)]
        windows: Option<Vec<Window>>,
        #[serde(default)]
        unrestricted: Option<bool>,
    },
    Regex {
        regex: String,
        #[serde(default)]
        windows: Option<Vec<Window>>,
        #[serde(default)]
        unrestricted: Option<bool>,
    },
    Default {
        #[serde(default)]
        windows: Option<Vec<Window>>,
        #[serde(default)]
        unrestricted: Option<bool>,
    },
}

/// How a `SaslLimitRule` selects which requests it applies to.
#[derive(Debug, Clone)]
pub enum Matcher {
    Username(String),
    Regex(Regex),
}

/// A matcher paired with the plan to enforce against whatever it matches.
#[derive(Debug, Clone)]
pub struct SaslLimitRule {
    pub matcher: Matcher,
    pub plan: CheckPlan,
}

impl SaslLimitRule {
    /// Returns whether this rule applies to `sasl_username`.
    pub fn matches(&self, sasl_username: &str) -> bool {
        match &self.matcher {
            Matcher::Username(username) => username == sasl_username,
            Matcher::Regex(regex) => regex.is_match(sasl_username),
        }
    }
}

/// The default value of `redis_key_prefix` when the config file omits it.
fn default_key_prefix() -> String { "postfix-ratelimitd".to_string() }

/// The default value of `redis.db` when the config file omits it - Redis and
/// Valkey both default a connection to database 0 when none is selected.
fn default_db() -> i64 { 0 }

/// The shortest window duration accepted. Chosen for sanity as an anti-abuse
/// email rate limit (sub-minute windows suit burst API protection more than
/// SMTP abuse, which is caught by hourly/daily thresholds instead), and
/// comfortably above the point where `BUCKET_TARGET_COUNT` needs no help from
/// clamping to `MIN_BUCKET_SIZE`.
const MIN_WINDOW_DURATION: Duration = Duration::from_mins(1);

/// The longest window duration accepted - the longest possible calendar
/// month.
const MAX_WINDOW_DURATION: Duration = Duration::from_hours(31 * 24);

/// Windows are aggregated into time buckets rather than storing one entry per
/// message (see `check_and_record.lua`). This is the number of buckets a
/// window is aggregated into, for any window whose resulting bucket size
/// doesn't need clamping to `MIN_BUCKET_SIZE` or `MAX_BUCKET_SIZE` - giving a
/// target overcount of `1/BUCKET_TARGET_COUNT` (2%) of the window's own
/// duration.
pub const BUCKET_TARGET_COUNT: u64 = 50;

/// The smallest bucket size ever used, regardless of what
/// `BUCKET_TARGET_COUNT` would otherwise compute for a very short window.
const MIN_BUCKET_SIZE: Duration = Duration::from_secs(1);

/// The largest bucket size ever used, regardless of what
/// `BUCKET_TARGET_COUNT` would otherwise compute for a very long window - a
/// day. Doesn't need to itself be a power of two: `bucket_size` only ever
/// compares a candidate doubling (always a power of two) against this value,
/// so whatever clears that comparison is already the largest power of two not
/// exceeding it, with no separate rounding step needed. Chosen independently
/// of `BUCKET_TARGET_COUNT` and `MAX_WINDOW_DURATION` rather than derived
/// from them, so it doesn't need retuning whenever either of those does; a
/// window needs to be at least `BUCKET_TARGET_COUNT * MAX_BUCKET_SIZE` long
/// to ever reach this clamp, which at the current `BUCKET_TARGET_COUNT` is
/// longer than `MAX_WINDOW_DURATION` allows - this is currently unreachable,
/// not dead: raising either constant later can make it live again without
/// any change here.
const MAX_BUCKET_SIZE: Duration = Duration::from_hours(24);

/// Selects the Redis hash bucket size to aggregate a window's messages into:
/// the largest power-of-two multiple of `MIN_BUCKET_SIZE`, up to
/// `MAX_BUCKET_SIZE`, for which `duration` still spans at least
/// `BUCKET_TARGET_COUNT` of them.
pub(crate) fn bucket_size(duration: Duration) -> Duration {
    let max_secs = MAX_BUCKET_SIZE.as_secs();
    let mut secs = MIN_BUCKET_SIZE.as_secs();
    while secs * 2 <= max_secs && duration.as_secs() / (secs * 2) >= BUCKET_TARGET_COUNT {
        secs *= 2;
    }
    Duration::from_secs(secs)
}

/// One window's position within a [`CheckPlan`]: which of its
/// `bucket_sizes` entries it shares, its span in seconds (the window's
/// configured duration), and its recipient limit. Sent to
/// `check_and_record.lua` as JSON, so field names are part of that script's
/// contract - see its ARGV comment.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct PlannedWindow {
    pub key_index: usize,
    pub span_secs: u64,
    pub limit: u32,
}

/// The `bucket_sizes`/`retention_secs`/`windows` fields of a [`CheckPlan`],
/// factored out so `Limiter::check` can nest them into a request without
/// duplicating the fields making it up.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CheckPlanFields<'a> {
    pub(crate) bucket_sizes: &'a [u64],
    pub(crate) retention_secs: &'a [u64],
    pub(crate) windows: &'a [PlannedWindow],
}

/// The precomputed shape of a `check_and_record.lua` invocation for a set of
/// windows - built once when the config is loaded rather than on every
/// check, since bucket sizes and spans depend only on window durations, never
/// on a request. `bucket_sizes` is deduplicated: windows whose durations land
/// on the same bucket size share one entry, and `PlannedWindow::key_index`
/// points into it.
#[derive(Debug, Clone)]
pub struct CheckPlan {
    pub bucket_sizes: Vec<u64>,
    pub windows: Vec<PlannedWindow>,
    // The longest span (in seconds) any window sharing bucket_sizes[i] needs
    // retained - the widest of their spans, since a key must keep history for
    // whichever sharing window needs the most. check_and_record.lua uses this
    // directly for that key's EXPIRE and prune cutoff, rather than
    // re-deriving it from `windows` on every check.
    pub retention_secs: Vec<u64>,
}

impl CheckPlan {
    /// Builds a plan from a rule's windows - see the `CheckPlan` docs above.
    ///
    /// Two windows are checked against the exact same accumulated total
    /// exactly when their `span_secs` match - `span_secs` is just the
    /// window's own configured duration, and bucket size is a pure function
    /// of duration, so matching `span_secs` already guarantees matching
    /// `key_index` too; the reverse doesn't hold, since windows sharing a
    /// bucket size can still need different retentions. Either way, only
    /// the stricter (lower) of the matching limits can ever be the one that
    /// rejects, so the other is folded in rather than kept as a redundant
    /// entry.
    fn new(windows: &[Window]) -> CheckPlan {
        let mut bucket_sizes: Vec<u64> = Vec::new();
        let mut retention_secs: Vec<u64> = Vec::new();
        let mut planned_windows: Vec<PlannedWindow> = Vec::new();
        for window in windows {
            let size = bucket_size(window.duration).as_secs();
            let key_index = bucket_sizes.iter().position(|&existing| existing == size).unwrap_or_else(|| {
                bucket_sizes.push(size);
                retention_secs.push(0);
                bucket_sizes.len() - 1
            });
            let span_secs = window.duration.as_secs();
            retention_secs[key_index] = retention_secs[key_index].max(span_secs);

            match planned_windows.iter_mut().find(|w| w.key_index == key_index && w.span_secs == span_secs) {
                Some(existing) => existing.limit = existing.limit.min(window.count),
                None => planned_windows.push(PlannedWindow { key_index, span_secs, limit: window.count }),
            }
        }
        CheckPlan { bucket_sizes, windows: planned_windows, retention_secs }
    }

    /// Borrows this plan's fields for nesting into a `Limiter::check` request
    /// - cheap, since it's just references, not a serialization.
    pub(crate) fn fields(&self) -> CheckPlanFields<'_> {
        CheckPlanFields {
            bucket_sizes: &self.bucket_sizes,
            retention_secs: &self.retention_secs,
            windows: &self.windows,
        }
    }
}

/// A Postfix action to take when a check can't be completed.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FailureAction {
    /// Defer the message (fail closed). The safe default.
    Defer,
    /// Let the message through (fail open).
    Permit,
}

/// The default value of `on_redis_error` when the config file omits it.
fn default_redis_error_action() -> FailureAction { FailureAction::Defer }

/// The default value of `warn_on_unauthenticated` when the config file omits
/// it.
fn default_warn_on_unauthenticated() -> bool { true }

/// The config file's `[redis]` section.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRedisConfig {
    url: String,
    #[serde(default = "default_db")]
    db: i64,
    #[serde(default)]
    password_file: Option<PathBuf>,
    #[serde(default = "default_key_prefix")]
    key_prefix: String,
}

/// The config file's `[server]` section.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServerConfig {
    socket: PathBuf,
    #[serde(default = "default_redis_error_action")]
    on_redis_error: FailureAction,
    // Unauthenticated requests are always permitted (there's no SASL username to
    // rate-limit against) - this only controls whether that's logged, for a
    // deployment that intentionally shares a restriction class between
    // authenticated and unauthenticated traffic and doesn't want the warning.
    #[serde(default = "default_warn_on_unauthenticated")]
    warn_on_unauthenticated: bool,
}

/// The config file's shape, before `sasl` is validated and its regexes
/// compiled.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    redis: RawRedisConfig,
    server: RawServerConfig,
    #[serde(rename = "sasl")]
    sasl_limits: Vec<RawSaslLimitRule>,
}

/// The daemon's fully validated configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub redis_connection_info: ConnectionInfo,
    pub redis_key_prefix: String,
    pub on_redis_error: FailureAction,
    pub warn_on_unauthenticated: bool,
    pub socket: PathBuf,
    pub sasl_limits: Vec<SaslLimitRule>,
    pub default_plan: CheckPlan,
}

/// Why loading or validating a config file failed.
#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read { path: PathBuf, source: std::io::Error },
    #[error("failed to parse config file {path}: {source}")]
    Parse { path: PathBuf, source: Box<toml::de::Error> },
    #[error("invalid redis_url: {source}")]
    BadRedisUrl { source: redis::RedisError },
    #[error("redis_url already has a password and redis_password_file is also set; supply the password only one way")]
    AmbiguousPassword,
    #[error("failed to read redis_password_file {path}: {source}")]
    ReadPasswordFile { path: PathBuf, source: std::io::Error },
    #[error("invalid regex in sasl[{index}]: {source}")]
    BadRegex { index: usize, source: regex_lite::Error },
    #[error("sasl must contain exactly one `type = \"default\"` rule, found {count}")]
    DefaultCount { count: usize },
    #[error(
        "sasl[{index}] has no windows - a rule with nothing to check would silently exempt everything it matches \
         from rate limiting. If this rule is meant to have no limit, set `unrestricted = true` instead."
    )]
    NoWindows { index: usize },
    #[error(
        "sasl[{index}] has both `windows` and `unrestricted = true` - remove `windows` if this rule should have no \
         limit, or remove `unrestricted` if it should use those windows"
    )]
    WindowsWithUnrestricted { index: usize },
    #[error(
        "sasl[{index}] sets `unrestricted = false`, which has no effect alongside `windows` - omit the key \
         entirely, or remove `windows` and set `unrestricted = true` to disable rate limiting for this rule instead"
    )]
    RedundantUnrestrictedFalse { index: usize },
    #[error(
        "sasl[{index}] has a window duration of {duration:?}, but windows must be a whole number of seconds, at \
         least {MIN_WINDOW_DURATION:?}"
    )]
    WindowTooShort { index: usize, duration: Duration },
    #[error("sasl[{index}] has a window duration of {duration:?}, but windows must be at most {MAX_WINDOW_DURATION:?}")]
    WindowTooLong { index: usize, duration: Duration },
}

/// Rejects an empty `windows` list, or any window whose duration isn't a
/// whole number of seconds or falls outside `[MIN_WINDOW_DURATION,
/// MAX_WINDOW_DURATION]`.
fn validate_windows(index: usize, windows: &[Window]) -> Result<(), ConfigError> {
    if windows.is_empty() {
        return Err(ConfigError::NoWindows { index });
    }
    for window in windows {
        if window.duration.subsec_nanos() != 0 || window.duration < MIN_WINDOW_DURATION {
            return Err(ConfigError::WindowTooShort { index, duration: window.duration });
        }
        if window.duration > MAX_WINDOW_DURATION {
            return Err(ConfigError::WindowTooLong { index, duration: window.duration });
        }
    }
    Ok(())
}

/// Builds the `CheckPlan` for one rule's `windows`/`unrestricted` pair - an
/// empty plan that never records anything and always permits, when
/// `unrestricted` is explicitly `true`, or a validated plan built from
/// `windows` otherwise.
///
/// `unrestricted = false` alongside real `windows` is rejected rather than
/// accepted as a no-op: its effect there (use `windows` normally) is
/// identical to simply omitting the key, so writing it out explicitly is far
/// more likely to be a misunderstanding worth catching than a deliberate
/// no-op worth silently accepting. `unrestricted = false` with no `windows`
/// at all isn't a redundant annotation on otherwise-valid config, though -
/// it's the same "nothing configured" problem as omitting both keys, so it's
/// reported as that instead. `windows` set alongside `unrestricted = true` is
/// rejected too, since having both leaves it unclear which one the reader
/// should trust.
fn build_plan(
    index: usize, windows: Option<Vec<Window>>, unrestricted: Option<bool>,
) -> Result<CheckPlan, ConfigError> {
    match (windows, unrestricted) {
        (None, Some(true)) => Ok(CheckPlan::new(&[])),
        (Some(_), Some(true)) => Err(ConfigError::WindowsWithUnrestricted { index }),
        (Some(_), Some(false)) => Err(ConfigError::RedundantUnrestrictedFalse { index }),
        (Some(windows), None) => {
            validate_windows(index, &windows)?;
            Ok(CheckPlan::new(&windows))
        }
        (None, Some(false) | None) => Err(ConfigError::NoWindows { index }),
    }
}

impl Config {
    /// Reads, parses, and validates the config file at `path`.
    #[allow(clippy::missing_panics_doc)] // the only panic is an internal invariant, not a caller-facing condition
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text =
            std::fs::read_to_string(path).map_err(|source| ConfigError::Read { path: path.to_path_buf(), source })?;
        let raw: RawConfig = toml::from_str(&text)
            .map_err(|source| ConfigError::Parse { path: path.to_path_buf(), source: Box::new(source) })?;

        let mut redis_connection_info =
            raw.redis.url.as_str().into_connection_info().map_err(|source| ConfigError::BadRedisUrl { source })?;
        let mut redis_settings = redis_connection_info.redis_settings().clone().set_db(raw.redis.db);
        if let Some(path) = raw.redis.password_file {
            if redis_settings.password().is_some() {
                return Err(ConfigError::AmbiguousPassword);
            }
            let password =
                std::fs::read_to_string(&path).map_err(|source| ConfigError::ReadPasswordFile { path, source })?;
            redis_settings = redis_settings.set_password(password.trim_end());
        }
        redis_connection_info = redis_connection_info.set_redis_settings(redis_settings);

        let default_count =
            raw.sasl_limits.iter().filter(|rule| matches!(rule, RawSaslLimitRule::Default { .. })).count();
        if default_count != 1 {
            return Err(ConfigError::DefaultCount { count: default_count });
        }

        let mut sasl_limits = Vec::with_capacity(raw.sasl_limits.len() - 1);
        let mut default_plan = None;
        for (index, rule) in raw.sasl_limits.into_iter().enumerate() {
            match rule {
                RawSaslLimitRule::Username { username, windows, unrestricted } => {
                    let plan = build_plan(index, windows, unrestricted)?;
                    sasl_limits.push(SaslLimitRule { matcher: Matcher::Username(username), plan });
                }
                RawSaslLimitRule::Regex { regex, windows, unrestricted } => {
                    let plan = build_plan(index, windows, unrestricted)?;
                    let regex = Regex::new(&regex).map_err(|source| ConfigError::BadRegex { index, source })?;
                    sasl_limits.push(SaslLimitRule { matcher: Matcher::Regex(regex), plan });
                }
                RawSaslLimitRule::Default { windows, unrestricted } => {
                    default_plan = Some(build_plan(index, windows, unrestricted)?);
                }
            }
        }

        Ok(Config {
            redis_connection_info,
            redis_key_prefix: raw.redis.key_prefix,
            on_redis_error: raw.server.on_redis_error,
            warn_on_unauthenticated: raw.server.warn_on_unauthenticated,
            socket: raw.server.socket,
            sasl_limits,
            default_plan: default_plan.expect("default_count == 1 guarantees exactly one Default entry was seen"),
        })
    }

    /// Returns the plan to enforce for `sasl_username`: the first matching
    /// rule's, or the default plan if nothing else matches.
    #[must_use]
    pub fn plan_for(&self, sasl_username: &str) -> &CheckPlan {
        self.sasl_limits.iter().find(|rule| rule.matches(sasl_username)).map_or(&self.default_plan, |rule| &rule.plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes `toml` to a temp file and loads it, mirroring real config file
    /// usage.
    fn load(toml: impl std::fmt::Display) -> Result<Config, ConfigError> {
        let file = tempfile::NamedTempFile::new().expect("create temp file");
        std::fs::write(file.path(), toml.to_string()).expect("write temp file");
        Config::load(file.path())
    }

    fn window(count: i64, duration: &str) -> toml::Value {
        toml::Value::Table(toml::toml! {
            count = count
            duration = duration
        })
    }

    /// A minimal valid config with a single `type = "default"` rule - the
    /// shape most tests only need incidentally, to reach whatever validation
    /// or behavior they're actually exercising.
    fn default_config(windows: Vec<toml::Value>) -> toml::Table {
        toml::toml! {
            redis.url = "redis://127.0.0.1:6379"
            redis.db = 1
            server.socket = "/tmp/policy"

            [[sasl]]
            type = "default"
            windows = windows
        }
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let toml = toml::toml! {
            redis.url = "redis://127.0.0.1:6379"
            redis.db = 1
            server.socket = "/tmp/policy"
            server.on_redis_eror = "permit"

            [[sasl]]
            type = "default"
            windows = [ { count = 1, duration = "1h" } ]
        };
        assert!(matches!(load(toml), Err(ConfigError::Parse { .. })));
    }

    #[test]
    fn zero_default_rules_is_rejected() {
        let toml = toml::toml! {
            redis.url = "redis://127.0.0.1:6379"
            redis.db = 1
            server.socket = "/tmp/policy"

            [[sasl]]
            type = "username"
            username = "alice"
            windows = [ { count = 1, duration = "1h" } ]
        };
        assert!(matches!(load(toml), Err(ConfigError::DefaultCount { count: 0 })));
    }

    #[test]
    fn multiple_default_rules_is_rejected() {
        let toml = toml::toml! {
            redis.url = "redis://127.0.0.1:6379"
            redis.db = 1
            server.socket = "/tmp/policy"

            [[sasl]]
            type = "default"
            windows = [ { count = 1, duration = "1h" } ]

            [[sasl]]
            type = "default"
            windows = [ { count = 2, duration = "1h" } ]
        };
        assert!(matches!(load(toml), Err(ConfigError::DefaultCount { count: 2 })));
    }

    #[test]
    fn default_rule_position_does_not_matter() {
        let toml = toml::toml! {
            redis.url = "redis://127.0.0.1:6379"
            redis.db = 1
            server.socket = "/tmp/policy"

            [[sasl]]
            type = "default"
            windows = [ { count = 1, duration = "1h" } ]

            [[sasl]]
            type = "username"
            username = "alice"
            windows = [ { count = 2, duration = "1h" } ]
        };
        let config = load(toml).expect("default rule need not be last");
        assert_eq!(config.plan_for("alice").windows[0].limit, 2);
        assert_eq!(config.plan_for("bob").windows[0].limit, 1);
    }

    #[test]
    fn subsecond_window_duration_is_rejected() {
        let toml = default_config(vec![window(1, "500ms")]);
        assert!(matches!(load(toml), Err(ConfigError::WindowTooShort { index: 0, .. })));
    }

    #[test]
    fn zero_second_window_duration_is_rejected() {
        let toml = default_config(vec![window(1, "0s")]);
        assert!(matches!(load(toml), Err(ConfigError::WindowTooShort { index: 0, .. })));
    }

    #[test]
    fn window_duration_under_60s_is_rejected() {
        let toml = default_config(vec![window(1, "59s")]);
        assert!(matches!(load(toml), Err(ConfigError::WindowTooShort { index: 0, .. })));
    }

    #[test]
    fn empty_windows_is_rejected() {
        let toml = default_config(vec![]);
        assert!(matches!(load(toml), Err(ConfigError::NoWindows { index: 0 })));
    }

    #[test]
    fn unrestricted_true_is_accepted_and_matches_everything() {
        let toml = toml::toml! {
            redis.url = "redis://127.0.0.1:6379"
            redis.db = 1
            server.socket = "/tmp/policy"

            [[sasl]]
            type = "username"
            username = "alice"
            unrestricted = true

            [[sasl]]
            type = "default"
            windows = [ { count = 1, duration = "1h" } ]
        };
        let config = load(toml).expect("unrestricted = true should be accepted");
        let plan = config.plan_for("alice");
        assert!(plan.bucket_sizes.is_empty(), "an unrestricted plan should have no windows to check");
    }

    #[test]
    fn unrestricted_false_alongside_windows_is_rejected() {
        let toml = toml::toml! {
            redis.url = "redis://127.0.0.1:6379"
            redis.db = 1
            server.socket = "/tmp/policy"

            [[sasl]]
            type = "default"
            windows = [ { count = 1, duration = "1h" } ]
            unrestricted = false
        };
        assert!(matches!(load(toml), Err(ConfigError::RedundantUnrestrictedFalse { index: 0 })));
    }

    #[test]
    fn unrestricted_false_alone_is_rejected_as_no_windows() {
        let toml = toml::toml! {
            redis.url = "redis://127.0.0.1:6379"
            redis.db = 1
            server.socket = "/tmp/policy"

            [[sasl]]
            type = "default"
            unrestricted = false
        };
        assert!(matches!(load(toml), Err(ConfigError::NoWindows { index: 0 })));
    }

    #[test]
    fn windows_alongside_unrestricted_true_is_rejected() {
        let toml = toml::toml! {
            redis.url = "redis://127.0.0.1:6379"
            redis.db = 1
            server.socket = "/tmp/policy"

            [[sasl]]
            type = "default"
            windows = [ { count = 1, duration = "1h" } ]
            unrestricted = true
        };
        assert!(matches!(load(toml), Err(ConfigError::WindowsWithUnrestricted { index: 0 })));
    }

    #[test]
    fn window_duration_of_exactly_60s_is_accepted() {
        let toml = default_config(vec![window(1, "60s")]);
        assert!(load(toml).is_ok());
    }

    #[test]
    fn bucket_size_hits_target_count_at_min_window_duration() {
        assert_eq!(bucket_size(MIN_WINDOW_DURATION), MIN_BUCKET_SIZE);
    }

    #[test]
    fn bucket_size_at_max_window_duration_does_not_yet_reach_the_clamp() {
        // At the current BUCKET_TARGET_COUNT, a window needs to be longer than
        // MAX_WINDOW_DURATION allows to ever reach MAX_BUCKET_SIZE's clamp
        // (see its own doc comment) - 32768s, not 65536s (the largest power of
        // two MAX_BUCKET_SIZE, a day, would round down to), is the actual
        // ceiling reached here. Pinned so a change to either constant that
        // makes 65536s reachable again is a deliberate, visible decision, not
        // a silent side effect.
        assert_eq!(bucket_size(MAX_WINDOW_DURATION), Duration::from_secs(32768));
    }

    #[test]
    fn bucket_size_never_exceeds_the_target_fraction_of_duration() {
        // check_and_record.lua counts a boundary bucket in full as soon as
        // any part of it is still within the window, which can overcount a
        // window by up to one bucket_size. This is the guarantee that keeps
        // that overcount bounded to no more than 1/BUCKET_TARGET_COUNT (2%)
        // of the window's own duration, for every valid window duration
        // whether or not it lands exactly on a ladder rung's boundary.
        // Exhaustive over every second in the valid range rather than
        // sampled, since it's cheap enough (milliseconds) not to need to be.
        let mut duration = MIN_WINDOW_DURATION;
        while duration <= MAX_WINDOW_DURATION {
            let secs = duration.as_secs();
            let size = bucket_size(duration).as_secs();
            assert!(
                size * BUCKET_TARGET_COUNT <= secs,
                "{duration:?} has bucket_size {size}s, exceeding the 1/{BUCKET_TARGET_COUNT} bound"
            );
            duration += Duration::from_secs(1);
        }
    }

    #[test]
    fn window_duration_over_31_days_is_rejected() {
        let toml = default_config(vec![window(1, "32d")]);
        assert!(matches!(load(toml), Err(ConfigError::WindowTooLong { index: 0, .. })));
    }

    #[test]
    fn window_duration_of_exactly_31_days_is_accepted() {
        let toml = default_config(vec![window(1, "31d")]);
        assert!(load(toml).is_ok());
    }

    #[test]
    fn shared_bucket_size_retention_is_the_longer_windows_span() {
        // Chosen because they land on the same bucket size (checked below as
        // the test's premise, not assumed), so they share one key - its
        // retention must cover the longer (4200s) window, not just the first
        // one seen. The shared bucket size is derived from the real
        // bucket_size function rather than hardcoded, so this keeps testing
        // the same property under any legitimate retuning of
        // BUCKET_TARGET_COUNT or the bucket-size ladder.
        let short = Duration::from_hours(1);
        let long = Duration::from_mins(70);
        assert_eq!(bucket_size(short), bucket_size(long), "test premise: both durations should share a bucket size");

        let toml = default_config(vec![window(1, "3600s"), window(1, "4200s")]);
        let config = load(toml).expect("valid config");
        let plan = config.plan_for("anyone");
        assert_eq!(plan.bucket_sizes, vec![bucket_size(short).as_secs()], "both windows should share one bucket size");

        assert_eq!(plan.windows[0].span_secs, short.as_secs());
        assert_eq!(plan.windows[1].span_secs, long.as_secs());
        assert_eq!(plan.retention_secs, vec![long.as_secs()], "retention must cover the longer window's span");
    }

    #[test]
    fn windows_with_identical_span_keep_only_the_stricter_limit() {
        let toml = default_config(vec![window(100, "1h"), window(20, "1h")]);
        let config = load(toml).expect("valid config");
        let plan = config.plan_for("anyone");
        assert_eq!(plan.windows.len(), 1, "identical-span windows should collapse into one");
        assert_eq!(plan.windows[0].limit, 20, "the stricter (lower) limit should survive");
    }

    #[test]
    fn bad_redis_url_is_rejected() {
        let toml = toml::toml! {
            redis.url = "not a url"
            redis.db = 1
            server.socket = "/tmp/policy"

            [[sasl]]
            type = "default"
            windows = [ { count = 1, duration = "1h" } ]
        };
        assert!(matches!(load(toml), Err(ConfigError::BadRedisUrl { .. })));
    }

    #[test]
    fn password_in_url_and_password_file_together_is_rejected() {
        let password_file = tempfile::NamedTempFile::new().expect("create temp file");
        std::fs::write(password_file.path(), "secret").expect("write password file");
        let path = password_file.path().display().to_string();
        let toml = toml::toml! {
            redis.url = "redis://:embedded@127.0.0.1:6379"
            redis.db = 1
            redis.password_file = path
            server.socket = "/tmp/policy"

            [[sasl]]
            type = "default"
            windows = [ { count = 1, duration = "1h" } ]
        };
        assert!(matches!(load(toml), Err(ConfigError::AmbiguousPassword)));
    }

    #[test]
    fn missing_password_file_is_rejected() {
        let toml = toml::toml! {
            redis.url = "redis://127.0.0.1:6379"
            redis.db = 1
            redis.password_file = "/nonexistent/path"
            server.socket = "/tmp/policy"

            [[sasl]]
            type = "default"
            windows = [ { count = 1, duration = "1h" } ]
        };
        assert!(matches!(load(toml), Err(ConfigError::ReadPasswordFile { .. })));
    }

    #[test]
    fn password_in_url_alone_is_used() {
        let toml = toml::toml! {
            redis.url = "redis://:embedded-pw@127.0.0.1:6379"
            redis.db = 1
            server.socket = "/tmp/policy"

            [[sasl]]
            type = "default"
            windows = [ { count = 1, duration = "1h" } ]
        };
        let config = load(toml).expect("valid config with url-embedded password");
        assert_eq!(config.redis_connection_info.redis_settings().password(), Some("embedded-pw"));
    }

    #[test]
    fn password_file_alone_is_used_and_trimmed() {
        let password_file = tempfile::NamedTempFile::new().expect("create temp file");
        std::fs::write(password_file.path(), "file-pw\n").expect("write password file");
        let path = password_file.path().display().to_string();
        let toml = toml::toml! {
            redis.url = "redis://127.0.0.1:6379"
            redis.db = 1
            redis.password_file = path
            server.socket = "/tmp/policy"

            [[sasl]]
            type = "default"
            windows = [ { count = 1, duration = "1h" } ]
        };
        let config = load(toml).expect("valid config with password file");
        assert_eq!(config.redis_connection_info.redis_settings().password(), Some("file-pw"));
    }

    #[test]
    fn on_redis_error_defaults_to_defer() {
        let toml = default_config(vec![window(1, "1h")]);
        let config = load(toml).expect("valid config");
        assert!(matches!(config.on_redis_error, FailureAction::Defer));
    }

    #[test]
    fn warn_on_unauthenticated_defaults_to_true() {
        let toml = default_config(vec![window(1, "1h")]);
        let config = load(toml).expect("valid config");
        assert!(config.warn_on_unauthenticated);
    }

    #[test]
    fn a_representative_config_loads_successfully() {
        let contractor_regex = r"@contractors\.example\.com$";
        let toml = toml::toml! {
            [redis]
            url = "redis://127.0.0.1:6379"
            db = 1

            [server]
            socket = "/tmp/policy"

            [[sasl]]
            type = "username"
            username = "alice"
            windows = [ { count = 20, duration = "1h" }, { count = 100, duration = "1d" } ]

            [[sasl]]
            type = "regex"
            regex = contractor_regex
            windows = [ { count = 10, duration = "1h" } ]

            [[sasl]]
            type = "default"
            windows = [ { count = 50, duration = "1h" }, { count = 200, duration = "1d" } ]
        };
        let config = load(toml).expect("valid representative config");
        assert_eq!(config.plan_for("alice").windows[0].limit, 20);
        assert_eq!(config.plan_for("bob@contractors.example.com").windows[0].limit, 10);
        assert_eq!(config.plan_for("nobody").windows[0].limit, 50);
    }
}
