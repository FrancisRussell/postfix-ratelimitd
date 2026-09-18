use crate::config::Config;
use crate::limiter::Limiter;

/// The daemon's current config and matching rate-limiter, bundled as one value so a reload swaps
/// both atomically behind a single `ArcSwap` - a reader can never observe one paired with a stale
/// version of the other.
#[derive(Debug, Clone)]
pub struct RuntimeState {
    pub config: Config,
    pub limiter: Limiter,
}
