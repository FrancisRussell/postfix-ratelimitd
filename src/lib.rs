#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![forbid(unsafe_code)]

pub mod config;
pub mod control;
pub mod limiter;
pub mod protocol;
pub mod state;

/// Policy response text shared between the daemon binary and its integration
/// tests.
pub const ACTION_DUNNO: &str = "dunno";
pub const ACTION_SERVICE_UNAVAILABLE: &str = "defer_if_permit Service temporarily unavailable";
pub const ACTION_RATE_LIMITED: &str = "defer_if_permit Recipient rate limit exceeded, retry later";
pub const ACTION_MISCONFIGURED: &str = "defer_if_permit Rate limit service misconfigured or broken, check \
                                         smtpd_data_restrictions/smtpd_end_of_data_restrictions wiring - see \
                                         the README";

/// The environment variable that must be set to acknowledge that a binary built with the integration-tests feature is
/// intentionally being run.
pub const INTEGRATION_TEST_ACKNOWLEDGMENT_ENV_VAR: &str = "POSTFIX_RATELIMITD_INTEGRATION_TEST_BUILD";
