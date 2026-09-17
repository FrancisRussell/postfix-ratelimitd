//! The admin control socket: a second, optional Unix socket (see
//! `Config::control_socket`) speaking [JSON-RPC 2.0](rpc) over newline-delimited JSON, so an
//! operator can check the socket is reachable ([`PING_METHOD`]) or ask for a SASL identity's
//! current rate-limit status ([`LIMITS_SASL_METHOD`]) without inspecting Valkey keys by hand.
//! Disabled unless configured.
//!
//! The [`rpc`] submodule is the generic JSON-RPC envelope; everything in this module is specific
//! to the methods this daemon exposes over it.

pub mod rpc;

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use redis::aio::ConnectionManager;
pub use rpc::{ErrorCode, RpcError, RpcRequest, RpcResponse};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio_util::sync::CancellationToken;

use crate::config::{CheckPlan, Config};
use crate::limiter::{self, Limiter};

/// Hard cap on one request line's length, so a malformed or hostile client can't grow the read
/// buffer unbounded.
const MAX_CONTROL_REQUEST_BYTES: u64 = 64 * 1024;

/// A trivial reachability check: takes no params, replies `"pong"`. Unlike [`LIMITS_SASL_METHOD`]
/// it never touches `config`/`limiter`, so it only verifies the control socket itself is up, not
/// that Valkey is reachable too.
pub const PING_METHOD: &str = "ping";

/// This protocol's method name for a SASL identity's rate-limit status.
pub const LIMITS_SASL_METHOD: &str = "limits.sasl";

/// Builds a [`PING_METHOD`] request.
#[must_use]
pub fn new_ping_request(id: u64) -> RpcRequest { rpc::new_request(PING_METHOD, JsonValue::Null, id) }

/// [`LIMITS_SASL_METHOD`]'s `params` shape.
#[derive(Debug, Serialize, Deserialize)]
pub struct LimitsSaslParams {
    pub username: String,
}

/// Builds a [`LIMITS_SASL_METHOD`] request for `username`.
#[must_use]
#[allow(clippy::missing_panics_doc)] // the only panic is an internal invariant, not a caller-facing condition
pub fn new_limits_sasl_request(username: &str, id: u64) -> RpcRequest {
    let params = serde_json::to_value(LimitsSaslParams { username: username.to_string() })
        .expect("LimitsSaslParams contains no types that can fail to serialize");
    rpc::new_request(LIMITS_SASL_METHOD, params, id)
}

/// One window's live status, mirroring [`crate::config::PlannedWindow`] but reporting a current
/// count rather than planned shape.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WindowStatus {
    pub span_secs: u64,
    pub limit: u32,
    pub current_total: u32,
}

/// The `result` payload of a successful [`LIMITS_SASL_METHOD`] reply.
///
/// `#[serde(untagged)]` is unambiguous here since the two variants have disjoint field sets.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StatusResponse {
    /// `unrestricted` is always `true` and carries no information of its own - it exists only so
    /// this variant serializes as a recognizable `{"unrestricted": true}` object rather than an
    /// empty one.
    Unrestricted {
        unrestricted: bool,
    },
    Limited {
        computed_at: u64,
        windows: Vec<WindowStatus>,
    },
}

/// Computes `username`'s current status against `plan` via plain reads (no
/// `check_and_record.lua` invocation - nothing is being recorded).
async fn compute_sasl_status(
    connection_manager: &mut ConnectionManager, key_prefix: &str, plan: &CheckPlan, username: &str,
) -> redis::RedisResult<StatusResponse> {
    if plan.bucket_sizes.is_empty() {
        return Ok(StatusResponse::Unrestricted { unrestricted: true });
    }

    let identity = limiter::identity(limiter::SASL_IDENTITY_KIND, username);

    // Same TIME call check_and_record.lua makes, rather than this host's local clock, so status
    // can't disagree with real enforcement under clock skew between this daemon and Valkey.
    let time: Vec<String> = redis::cmd("TIME").query_async(connection_manager).await?;
    let now: u64 = time[0].parse().map_err(|_| {
        redis::RedisError::from((redis::ErrorKind::UnexpectedReturnType, "TIME reply did not parse as an integer"))
    })?;

    let mut buckets_by_key = Vec::with_capacity(plan.bucket_sizes.len());
    for &bucket_size in &plan.bucket_sizes {
        let key = limiter::bucket_key(key_prefix, &identity, bucket_size);
        let fields: HashMap<u64, u32> = redis::cmd("HGETALL").arg(&key).query_async(connection_manager).await?;
        buckets_by_key.push(fields);
    }

    let windows = plan
        .windows
        .iter()
        .map(|window| {
            let bucket_size = plan.bucket_sizes[window.key_index];
            let oldest = now.saturating_sub(window.span_secs);
            // Same one-line boundary rule as check_and_record.lua: count a bucket in full as
            // long as its end hasn't passed the cutoff yet.
            let current_total = buckets_by_key[window.key_index]
                .iter()
                .filter(|&(id, _)| (*id + 1) * bucket_size > oldest)
                .map(|(_, &count)| count)
                .sum();
            WindowStatus { span_secs: window.span_secs, limit: window.limit, current_total }
        })
        .collect();

    Ok(StatusResponse::Limited { computed_at: now, windows })
}

/// Dispatches one already-deserialized request to a response, never failing outright - every
/// error becomes an `rpc::failure` rather than an `Err`, since a malformed request still gets a
/// reply, just one describing the problem.
async fn dispatch(request: RpcRequest, config: &ArcSwap<Config>, limiter: &ArcSwap<Limiter>) -> RpcResponse {
    match request.method.as_str() {
        PING_METHOD => rpc::success(request.id, JsonValue::String("pong".to_string())),
        LIMITS_SASL_METHOD => {
            let params: LimitsSaslParams = match serde_json::from_value(request.params.unwrap_or(JsonValue::Null)) {
                Ok(params) => params,
                Err(err) => {
                    return rpc::failure(request.id, ErrorCode::InvalidParams, &format!("invalid params: {err}"));
                }
            };
            let current_config = config.load_full();
            let current_limiter = limiter.load_full();
            let plan = current_config.plan_for(&params.username);
            let mut connection_manager = current_limiter.connection_manager();
            match compute_sasl_status(&mut connection_manager, current_limiter.key_prefix(), plan, &params.username)
                .await
            {
                Ok(status) => rpc::success(
                    request.id,
                    serde_json::to_value(status).expect("StatusResponse contains no types that can fail to serialize"),
                ),
                Err(err) => {
                    log::warn!("error checking control-socket status for {:?}: {err}", params.username);
                    rpc::failure(request.id, ErrorCode::InternalError, "error checking status")
                }
            }
        }
        method => rpc::failure(request.id, ErrorCode::MethodNotFound, &format!("unknown method {method:?}")),
    }
}

/// Parses and dispatches one request line into a response.
async fn handle_line(line: &str, config: &ArcSwap<Config>, limiter: &ArcSwap<Limiter>) -> RpcResponse {
    // Two stages, matching the spec's distinction between the two: invalid JSON is a parse
    // error, while valid JSON that isn't a well-formed Request object (missing/wrong-typed
    // jsonrpc/method) is an invalid request. A jsonrpc version other than "2.0" is rejected this
    // way; an absent jsonrpc member is not - it defaults to "2.0" instead (see rpc's own tests),
    // low-risk given this socket is already owner-only. Both stages reply with no id, which
    // serializes as `null`, since neither can be trusted to have found a real one.
    match serde_json::from_str::<JsonValue>(line) {
        Err(err) => rpc::failure(None, ErrorCode::ParseError, &format!("invalid JSON: {err}")),
        Ok(value) => match serde_json::from_value::<RpcRequest>(value) {
            Err(err) => rpc::failure(None, ErrorCode::InvalidRequest, &format!("invalid request: {err}")),
            Ok(request) => dispatch(request, config, limiter).await,
        },
    }
}

/// Handles one control-socket connection: reads request lines until the connection closes or
/// `cancel` fires, replying to each with one response line. An oversized or EOF-truncated line
/// gets one best-effort error reply and the connection is then closed.
pub async fn handle_connection(
    stream: UnixStream, config: Arc<ArcSwap<Config>>, limiter: Arc<ArcSwap<Limiter>>, cancel: CancellationToken,
) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    loop {
        let mut line = String::new();
        // A fresh `take` per line, not once for the whole connection, since each line is its
        // own independent request under this cap.
        let mut line_reader = (&mut reader).take(MAX_CONTROL_REQUEST_BYTES);
        let read = tokio::select! {
            () = cancel.cancelled() => return,
            result = line_reader.read_line(&mut line) => result,
        };
        let read = match read {
            Ok(read) => read,
            Err(err) => {
                log::warn!("error reading control request: {err}");
                return;
            }
        };
        if read == 0 {
            return;
        }
        if !line.ends_with('\n') {
            let message = if line_reader.limit() == 0 {
                "control request exceeded max size"
            } else {
                "connection closed mid-request"
            };
            let _ = write_response(&mut writer, &rpc::failure(None, ErrorCode::InvalidRequest, message)).await;
            return;
        }

        let response = handle_line(line.trim_end_matches(['\n', '\r']), &config, &limiter).await;
        if write_response(&mut writer, &response).await.is_err() {
            return;
        }
    }
}

async fn write_response(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin), response: &RpcResponse,
) -> std::io::Result<()> {
    let line = serde_json::to_string(response).expect("RpcResponse contains no types that can fail to serialize");
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\n").await
}

// dispatch()/compute_sasl_status()'s branches (unrestricted rule, unknown method, invalid
// params, the boundary-counting arithmetic) all need either a real Config or a real
// Limiter/Valkey connection to exercise meaningfully - see the control_socket_* tests in
// tests/valkey_integration.rs instead. The JSON-RPC envelope shape itself, which needs neither,
// is unit-tested in rpc.rs.
