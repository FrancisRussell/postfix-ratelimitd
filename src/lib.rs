//! The daemon's core logic - `main.rs` is a thin binary shell (argument
//! parsing, logging setup, the accept loop) over these modules, kept in the
//! library so both it and this crate's integration tests share one
//! compilation of them rather than the binary having its own private copy.

#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]

pub mod config;
pub mod limiter;
pub mod protocol;

/// Policy response text shared between the daemon binary and its integration
/// tests, so a wording change can't drift out of sync between the two.
pub const ACTION_DUNNO: &str = "dunno";
pub const ACTION_SERVICE_UNAVAILABLE: &str = "defer_if_permit Service temporarily unavailable";
pub const ACTION_RATE_LIMITED: &str = "defer_if_permit Recipient rate limit exceeded, retry later";
pub const ACTION_MISCONFIGURED: &str = "defer_if_permit Rate limit service misconfigured or broken, check \
                                         smtpd_data_restrictions wiring - see the README";

/// Set to acknowledge that a binary built with the integration-tests feature
/// (which accepts a `now_override` policy attribute with no real Postfix
/// equivalent - see `protocol::Request::now_override`) is intentionally being
/// run, not shipped to production by mistake. Checked once at startup; the
/// process refuses to start without it. Shared between the daemon binary and
/// its integration tests so the two can't drift out of sync on the name.
pub const INTEGRATION_TEST_ACKNOWLEDGMENT_ENV_VAR: &str = "POSTFIX_RATELIMITD_INTEGRATION_TEST_BUILD";
