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

/// A `limits` entry as written in the config file, before its regex is
/// compiled.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum RawLimitRule {
    Username { username: String, windows: Vec<Window> },
    Regex { regex: String, windows: Vec<Window> },
    Default { windows: Vec<Window> },
}

/// How a `LimitRule` selects which requests it applies to.
#[derive(Debug, Clone)]
pub enum Matcher {
    Username(String),
    Regex(Regex),
}

/// A matcher paired with the plan to enforce against whatever it matches.
#[derive(Debug, Clone)]
pub struct LimitRule {
    pub matcher: Matcher,
    pub plan: CheckPlan,
}

impl LimitRule {
    /// Returns whether this rule applies to `sasl_username`.
    pub fn matches(&self, sasl_username: &str) -> bool {
        match &self.matcher {
            Matcher::Username(username) => username == sasl_username,
            Matcher::Regex(regex) => regex.is_match(sasl_username),
        }
    }
}

/// The default value of `redis_key_prefix` when the config file omits it.
fn default_key_prefix() -> String { "postfix-ratelimitd:".to_string() }

/// The shortest window duration accepted. Chosen for sanity as an anti-abuse
/// email rate limit (sub-minute windows suit burst API protection more than
/// SMTP abuse, which is caught by hourly/daily thresholds instead), and
/// comfortably above the point where `BUCKET_TARGET_COUNT` needs no help from
/// clamping to `MIN_BUCKET_SIZE`.
const MIN_WINDOW_DURATION: Duration = Duration::from_secs(60);

/// The longest window duration accepted - the longest possible calendar
/// month.
const MAX_WINDOW_DURATION: Duration = Duration::from_hours(31 * 24);

/// Windows are aggregated into time buckets rather than storing one entry per
/// message (see `check_and_record.lua`). This is the number of buckets a
/// window is aggregated into, for any window whose resulting bucket size
/// doesn't need clamping to `MIN_BUCKET_SIZE` or `MAX_BUCKET_SIZE` - giving a
/// target overcount of `1/BUCKET_TARGET_COUNT` (5%) of the window's own
/// duration.
const BUCKET_TARGET_COUNT: u64 = 20;

/// The smallest bucket size ever used, regardless of what
/// `BUCKET_TARGET_COUNT` would otherwise compute for a very short window.
const MIN_BUCKET_SIZE: Duration = Duration::from_secs(1);

/// The largest bucket size ever used, regardless of what
/// `BUCKET_TARGET_COUNT` would otherwise compute for a very long window - a
/// power of two, like every other bucket size, so it's a ladder rung rather
/// than a special case.
const MAX_BUCKET_SIZE: Duration = Duration::from_secs(65536);

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

/// The number of `bucket_size(duration)`-sized buckets needed to cover
/// `duration`, rounded up so a boundary bucket only partially within the
/// window is still counted in full rather than dropped.
pub(crate) fn lookback_buckets(duration: Duration) -> u64 {
    duration.as_secs().div_ceil(bucket_size(duration).as_secs())
}

/// One window's position within a [`CheckPlan`]: which of its
/// `bucket_sizes` entries it shares, its retention span in seconds
/// (`duration` rounded up to a whole number of buckets), and its recipient
/// limit. Sent to `check_and_record.lua` as JSON, so field names are part of
/// that script's contract - see its ARGV comment.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct PlannedWindow {
    pub key_index: usize,
    pub span_secs: u64,
    pub limit: u32,
}

/// The `bucket_sizes`/`retention_secs`/`windows` fields of a [`CheckPlan`],
/// factored out only so `CheckPlan::new` has something to serialize that
/// excludes its cached `json` field.
#[derive(Debug, Clone, Serialize)]
struct CheckPlanFields<'a> {
    bucket_sizes: &'a [u64],
    retention_secs: &'a [u64],
    windows: &'a [PlannedWindow],
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
    // Only read directly by this module's own tests; `Limiter::check` sends
    // `json` instead, since production code never needs anything but the
    // already-serialized form.
    #[cfg_attr(not(test), allow(dead_code))]
    pub windows: Vec<PlannedWindow>,
    // The longest span (in seconds) any window sharing bucket_sizes[i] needs
    // retained - the widest of their spans, since a key must keep history for
    // whichever sharing window needs the most. check_and_record.lua uses this
    // directly for that key's EXPIRE and prune cutoff, rather than
    // re-deriving it from `windows` on every check.
    #[cfg_attr(not(test), allow(dead_code))]
    pub retention_secs: Vec<u64>,
    json: String,
}

impl CheckPlan {
    /// Builds a plan from a rule's windows - see the `CheckPlan` docs above.
    fn new(windows: &[Window]) -> CheckPlan {
        let mut bucket_sizes: Vec<u64> = Vec::new();
        let mut retention_secs: Vec<u64> = Vec::new();
        let mut planned_windows = Vec::with_capacity(windows.len());
        for window in windows {
            let size = bucket_size(window.duration).as_secs();
            let key_index = match bucket_sizes.iter().position(|&existing| existing == size) {
                Some(index) => index,
                None => {
                    bucket_sizes.push(size);
                    retention_secs.push(0);
                    bucket_sizes.len() - 1
                }
            };
            let span_secs = lookback_buckets(window.duration) * size;
            retention_secs[key_index] = retention_secs[key_index].max(span_secs);
            planned_windows.push(PlannedWindow { key_index, span_secs, limit: window.count });
        }
        let json = serde_json::to_string(&CheckPlanFields {
            bucket_sizes: &bucket_sizes,
            retention_secs: &retention_secs,
            windows: &planned_windows,
        })
        .expect("CheckPlan contains no types that can fail to serialize");
        CheckPlan { bucket_sizes, windows: planned_windows, retention_secs, json }
    }

    /// This plan's `bucket_sizes`/`windows`, pre-serialized as JSON once at
    /// construction rather than on every check - see `Limiter::check`.
    pub fn json(&self) -> &str { &self.json }
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

/// The config file's shape, before `limits` is validated and its regexes
/// compiled.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    redis: RawRedisConfig,
    server: RawServerConfig,
    limits: Vec<RawLimitRule>,
}

/// The daemon's fully validated configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub redis_connection_info: ConnectionInfo,
    pub redis_key_prefix: String,
    pub on_redis_error: FailureAction,
    pub warn_on_unauthenticated: bool,
    pub socket: PathBuf,
    pub limits: Vec<LimitRule>,
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
    #[error("invalid regex in limits[{index}]: {source}")]
    BadRegex { index: usize, source: regex_lite::Error },
    #[error("limits must contain exactly one `type = \"default\"` rule, found {count}")]
    DefaultCount { count: usize },
    #[error(
        "limits[{index}] has a window duration of {duration:?}, but windows must be a whole number of seconds, at \
         least {MIN_WINDOW_DURATION:?}"
    )]
    WindowTooShort { index: usize, duration: Duration },
    #[error(
        "limits[{index}] has a window duration of {duration:?}, but windows must be at most {MAX_WINDOW_DURATION:?}"
    )]
    WindowTooLong { index: usize, duration: Duration },
}

/// Rejects any window whose duration isn't a whole number of seconds, or
/// falls outside `[MIN_WINDOW_DURATION, MAX_WINDOW_DURATION]`.
fn validate_windows(index: usize, windows: &[Window]) -> Result<(), ConfigError> {
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

impl Config {
    /// Reads, parses, and validates the config file at `path`.
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

        let default_count = raw.limits.iter().filter(|rule| matches!(rule, RawLimitRule::Default { .. })).count();
        if default_count != 1 {
            return Err(ConfigError::DefaultCount { count: default_count });
        }

        let mut limits = Vec::with_capacity(raw.limits.len() - 1);
        let mut default_plan = None;
        for (index, rule) in raw.limits.into_iter().enumerate() {
            match rule {
                RawLimitRule::Username { username, windows } => {
                    validate_windows(index, &windows)?;
                    limits.push(LimitRule { matcher: Matcher::Username(username), plan: CheckPlan::new(&windows) });
                }
                RawLimitRule::Regex { regex, windows } => {
                    validate_windows(index, &windows)?;
                    let regex = Regex::new(&regex).map_err(|source| ConfigError::BadRegex { index, source })?;
                    limits.push(LimitRule { matcher: Matcher::Regex(regex), plan: CheckPlan::new(&windows) });
                }
                RawLimitRule::Default { windows } => {
                    validate_windows(index, &windows)?;
                    default_plan = Some(CheckPlan::new(&windows));
                }
            }
        }

        Ok(Config {
            redis_connection_info,
            redis_key_prefix: raw.redis.key_prefix,
            on_redis_error: raw.server.on_redis_error,
            warn_on_unauthenticated: raw.server.warn_on_unauthenticated,
            socket: raw.server.socket,
            limits,
            default_plan: default_plan.expect("default_count == 1 guarantees exactly one Default entry was seen"),
        })
    }

    /// Returns the plan to enforce for `sasl_username`: the first matching
    /// rule's, or the default plan if nothing else matches.
    pub fn plan_for(&self, sasl_username: &str) -> &CheckPlan {
        self.limits.iter().find(|rule| rule.matches(sasl_username)).map(|rule| &rule.plan).unwrap_or(&self.default_plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes `toml` to a temp file and loads it, mirroring real config file
    /// usage.
    fn load(toml: &str) -> Result<Config, ConfigError> {
        let file = tempfile::NamedTempFile::new().expect("create temp file");
        std::fs::write(file.path(), toml).expect("write temp file");
        Config::load(file.path())
    }

    const BASE: &str = "redis.url = \"redis://127.0.0.1:6379\"\nredis.db = 1\nserver.socket = \"/tmp/policy\"\n";

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let toml = format!(
            "{BASE}\n\
             server.on_redis_eror = \"permit\"\n\
             [[limits]]\n\
             type = \"default\"\n\
             windows = [ {{ count = 1, duration = \"1h\" }} ]\n"
        );
        assert!(matches!(load(&toml), Err(ConfigError::Parse { .. })));
    }

    #[test]
    fn zero_default_rules_is_rejected() {
        let toml = format!(
            "{BASE}\n\
             [[limits]]\n\
             type = \"username\"\n\
             username = \"alice\"\n\
             windows = [ {{ count = 1, duration = \"1h\" }} ]\n"
        );
        assert!(matches!(load(&toml), Err(ConfigError::DefaultCount { count: 0 })));
    }

    #[test]
    fn multiple_default_rules_is_rejected() {
        let toml = format!(
            "{BASE}\n\
             [[limits]]\n\
             type = \"default\"\n\
             windows = [ {{ count = 1, duration = \"1h\" }} ]\n\
             [[limits]]\n\
             type = \"default\"\n\
             windows = [ {{ count = 2, duration = \"1h\" }} ]\n"
        );
        assert!(matches!(load(&toml), Err(ConfigError::DefaultCount { count: 2 })));
    }

    #[test]
    fn default_rule_position_does_not_matter() {
        let toml = format!(
            "{BASE}\n\
             [[limits]]\n\
             type = \"default\"\n\
             windows = [ {{ count = 1, duration = \"1h\" }} ]\n\
             [[limits]]\n\
             type = \"username\"\n\
             username = \"alice\"\n\
             windows = [ {{ count = 2, duration = \"1h\" }} ]\n"
        );
        let config = load(&toml).expect("default rule need not be last");
        assert_eq!(config.plan_for("alice").windows[0].limit, 2);
        assert_eq!(config.plan_for("bob").windows[0].limit, 1);
    }

    #[test]
    fn subsecond_window_duration_is_rejected() {
        let toml = format!(
            "{BASE}\n\
             [[limits]]\n\
             type = \"default\"\n\
             windows = [ {{ count = 1, duration = \"500ms\" }} ]\n"
        );
        assert!(matches!(load(&toml), Err(ConfigError::WindowTooShort { index: 0, .. })));
    }

    #[test]
    fn zero_second_window_duration_is_rejected() {
        let toml = format!(
            "{BASE}\n\
             [[limits]]\n\
             type = \"default\"\n\
             windows = [ {{ count = 1, duration = \"0s\" }} ]\n"
        );
        assert!(matches!(load(&toml), Err(ConfigError::WindowTooShort { index: 0, .. })));
    }

    #[test]
    fn window_duration_under_60s_is_rejected() {
        let toml = format!(
            "{BASE}\n\
             [[limits]]\n\
             type = \"default\"\n\
             windows = [ {{ count = 1, duration = \"59s\" }} ]\n"
        );
        assert!(matches!(load(&toml), Err(ConfigError::WindowTooShort { index: 0, .. })));
    }

    #[test]
    fn window_duration_of_exactly_60s_is_accepted() {
        let toml = format!(
            "{BASE}\n\
             [[limits]]\n\
             type = \"default\"\n\
             windows = [ {{ count = 1, duration = \"60s\" }} ]\n"
        );
        assert!(load(&toml).is_ok());
    }

    #[test]
    fn bucket_size_hits_target_count_at_min_window_duration() {
        assert_eq!(bucket_size(MIN_WINDOW_DURATION), Duration::from_secs(2));
        assert_eq!(lookback_buckets(MIN_WINDOW_DURATION), 30);
    }

    #[test]
    fn bucket_size_is_clamped_to_max_at_max_window_duration() {
        assert_eq!(bucket_size(MAX_WINDOW_DURATION), MAX_BUCKET_SIZE);
        assert_eq!(lookback_buckets(MAX_WINDOW_DURATION), 41);
    }

    #[test]
    fn bucket_size_never_gives_fewer_than_target_count_buckets() {
        // Sweep representative durations across the whole valid range, checking the one
        // invariant the selection rule is supposed to guarantee everywhere: a window is
        // never aggregated into fewer than BUCKET_TARGET_COUNT buckets (only ever that
        // many or more), whether or not it lands exactly on a ladder rung's boundary.
        let mut duration = MIN_WINDOW_DURATION;
        while duration <= MAX_WINDOW_DURATION {
            assert!(
                lookback_buckets(duration) >= BUCKET_TARGET_COUNT,
                "{duration:?} only gets {} buckets",
                lookback_buckets(duration)
            );
            duration += Duration::from_secs(3600);
        }
    }

    #[test]
    fn window_duration_over_31_days_is_rejected() {
        let toml = format!(
            "{BASE}\n\
             [[limits]]\n\
             type = \"default\"\n\
             windows = [ {{ count = 1, duration = \"32d\" }} ]\n"
        );
        assert!(matches!(load(&toml), Err(ConfigError::WindowTooLong { index: 0, .. })));
    }

    #[test]
    fn window_duration_of_exactly_31_days_is_accepted() {
        let toml = format!(
            "{BASE}\n\
             [[limits]]\n\
             type = \"default\"\n\
             windows = [ {{ count = 1, duration = \"31d\" }} ]\n"
        );
        assert!(load(&toml).is_ok());
    }

    #[test]
    fn shared_bucket_size_retention_is_the_longer_windows_span() {
        // 3600s and 4200s both land on a 128s bucket size (see
        // config::bucket_size), so they share one key - its retention must
        // cover the longer (4200s) window, not just the first one seen.
        let toml = format!(
            "{BASE}\n\
             [[limits]]\n\
             type = \"default\"\n\
             windows = [ {{ count = 1, duration = \"3600s\" }}, {{ count = 1, duration = \"4200s\" }} ]\n"
        );
        let config = load(&toml).expect("valid config");
        let plan = config.plan_for("anyone");
        assert_eq!(plan.bucket_sizes, vec![128], "both windows should share one bucket size");
        assert_eq!(plan.windows[0].span_secs, 3712);
        assert_eq!(plan.windows[1].span_secs, 4224);
        assert_eq!(plan.retention_secs, vec![4224], "retention must cover the longer window's span");
    }

    #[test]
    fn bad_redis_url_is_rejected() {
        let toml = "redis.url = \"not a url\"\nredis.db = 1\nserver.socket = \"/tmp/policy\"\n\n\
                     [[limits]]\n\
                     type = \"default\"\n\
                     windows = [ { count = 1, duration = \"1h\" } ]\n";
        assert!(matches!(load(toml), Err(ConfigError::BadRedisUrl { .. })));
    }

    #[test]
    fn password_in_url_and_password_file_together_is_rejected() {
        let password_file = tempfile::NamedTempFile::new().expect("create temp file");
        std::fs::write(password_file.path(), "secret").expect("write password file");
        let toml = format!(
            "redis.url = \"redis://:embedded@127.0.0.1:6379\"\n\
             redis.db = 1\n\
             redis.password_file = \"{}\"\n\
             server.socket = \"/tmp/policy\"\n\n\
             [[limits]]\n\
             type = \"default\"\n\
             windows = [ {{ count = 1, duration = \"1h\" }} ]\n",
            password_file.path().display()
        );
        assert!(matches!(load(&toml), Err(ConfigError::AmbiguousPassword)));
    }

    #[test]
    fn missing_password_file_is_rejected() {
        let toml = format!(
            "{BASE}redis.password_file = \"/nonexistent/path\"\n\n\
             [[limits]]\n\
             type = \"default\"\n\
             windows = [ {{ count = 1, duration = \"1h\" }} ]\n"
        );
        assert!(matches!(load(&toml), Err(ConfigError::ReadPasswordFile { .. })));
    }

    #[test]
    fn password_in_url_alone_is_used() {
        let toml = "redis.url = \"redis://:embedded-pw@127.0.0.1:6379\"\nredis.db = 1\nserver.socket = \"/tmp/policy\"\n\n\
                     [[limits]]\n\
                     type = \"default\"\n\
                     windows = [ { count = 1, duration = \"1h\" } ]\n";
        let config = load(toml).expect("valid config with url-embedded password");
        assert_eq!(config.redis_connection_info.redis_settings().password(), Some("embedded-pw"));
    }

    #[test]
    fn password_file_alone_is_used_and_trimmed() {
        let password_file = tempfile::NamedTempFile::new().expect("create temp file");
        std::fs::write(password_file.path(), "file-pw\n").expect("write password file");
        let toml = format!(
            "{BASE}redis.password_file = \"{}\"\n\n\
             [[limits]]\n\
             type = \"default\"\n\
             windows = [ {{ count = 1, duration = \"1h\" }} ]\n",
            password_file.path().display()
        );
        let config = load(&toml).expect("valid config with password file");
        assert_eq!(config.redis_connection_info.redis_settings().password(), Some("file-pw"));
    }

    #[test]
    fn on_redis_error_defaults_to_defer() {
        let toml = format!(
            "{BASE}\n\
             [[limits]]\n\
             type = \"default\"\n\
             windows = [ {{ count = 1, duration = \"1h\" }} ]\n"
        );
        let config = load(&toml).expect("valid config");
        assert!(matches!(config.on_redis_error, FailureAction::Defer));
    }

    #[test]
    fn warn_on_unauthenticated_defaults_to_true() {
        let toml = format!(
            "{BASE}\n\
             [[limits]]\n\
             type = \"default\"\n\
             windows = [ {{ count = 1, duration = \"1h\" }} ]\n"
        );
        let config = load(&toml).expect("valid config");
        assert!(config.warn_on_unauthenticated);
    }

    #[test]
    fn a_representative_config_loads_successfully() {
        let toml = "[redis]\n\
             url = \"redis://127.0.0.1:6379\"\n\
             db = 1\n\n\
             [server]\n\
             socket = \"/tmp/policy\"\n\n\
             [[limits]]\n\
             type = \"username\"\n\
             username = \"alice\"\n\
             windows = [ { count = 20, duration = \"1h\" }, { count = 100, duration = \"1d\" } ]\n\
             [[limits]]\n\
             type = \"regex\"\n\
             regex = '@contractors\\.example\\.com$'\n\
             windows = [ { count = 10, duration = \"1h\" } ]\n\
             [[limits]]\n\
             type = \"default\"\n\
             windows = [ { count = 50, duration = \"1h\" }, { count = 200, duration = \"1d\" } ]\n";
        let config = load(toml).expect("valid representative config");
        assert_eq!(config.plan_for("alice").windows[0].limit, 20);
        assert_eq!(config.plan_for("bob@contractors.example.com").windows[0].limit, 10);
        assert_eq!(config.plan_for("nobody").windows[0].limit, 50);
    }
}
