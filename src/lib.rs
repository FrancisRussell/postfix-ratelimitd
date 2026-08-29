//! Policy response text shared between the daemon binary and its integration
//! tests, so a wording change can't drift out of sync between the two.

pub const ACTION_DUNNO: &str = "dunno";
pub const ACTION_SERVICE_UNAVAILABLE: &str = "defer_if_permit Service temporarily unavailable";
pub const ACTION_RATE_LIMITED: &str = "defer_if_permit Recipient rate limit exceeded, retry later";
pub const ACTION_MISCONFIGURED: &str = "defer_if_permit Rate limit service misconfigured or broken, check \
                                         smtpd_data_restrictions wiring - see the README";
