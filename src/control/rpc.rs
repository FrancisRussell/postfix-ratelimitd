//! Generic [JSON-RPC 2.0](https://www.jsonrpc.org/specification) envelope types - independent of
//! any particular method this daemon exposes over them.
//!
//! These are thin aliases over the [`json_rpc_types`] crate, pinned to the concrete type
//! parameters this daemon needs, rather than a hand-rolled envelope: the one invariant that
//! actually matters here - a response has *exactly one* of `result`/`error`, never both, never
//! neither - is enforced by that crate's `Response` being a real `Result` internally (so the
//! invalid states aren't just avoided by convention, they're unrepresentable), with a
//! `Deserialize` impl that rejects wire input violating it outright.

pub use json_rpc_types::ErrorCode;
use json_rpc_types::{Id, Version};
use serde_json::Value as JsonValue;

/// This daemon never attaches structured `data` to an error object.
pub type ErrorData = ();

/// The method-name type: a fixed 32-byte inline buffer, avoiding a heap allocation for a short,
/// statically-known name like [`super::LIMITS_SASL_METHOD`]. Reached via `json_rpc_types`'s own
/// re-export of `str-buf` rather than adding `str-buf` as a separate direct dependency.
pub type MethodName = json_rpc_types::str_buf::StrBuf<32>;

pub type RpcError = json_rpc_types::Error<ErrorData, String>;
pub type RpcRequest = json_rpc_types::Request<JsonValue, MethodName>;
pub type RpcResponse = json_rpc_types::Response<JsonValue, ErrorData, String>;

/// Builds a request for `method` with an integer `id` - the only shape this daemon's own client
/// ever needs to send.
#[must_use]
#[allow(clippy::missing_panics_doc)] // the only panic is an internal invariant, not a caller-facing condition
pub fn new_request(method: &str, params: JsonValue, id: u64) -> RpcRequest {
    RpcRequest {
        jsonrpc: Version::V2,
        method: MethodName::try_from(method).expect("method names are short static strings"),
        params: Some(params),
        id: Some(Id::Num(id)),
    }
}

/// Builds a successful response.
pub(crate) fn success(id: Option<Id>, result: JsonValue) -> RpcResponse { RpcResponse::result(Version::V2, result, id) }

/// Builds a failure response with a plain-text message and no structured error data.
pub(crate) fn failure(id: Option<Id>, code: ErrorCode, message: &str) -> RpcResponse {
    RpcResponse::error(Version::V2, RpcError::with_text_message(code, message), id)
}

#[cfg(test)]
mod tests {
    use super::RpcResponse;
    use crate::control::RpcRequest;

    // These pin down this module's headline claim - that `json_rpc_types` enforces "exactly one
    // of result/error" structurally, not by convention - against the real wire format, rather
    // than trusting the crate's own doc comments.

    #[test]
    fn response_with_both_result_and_error_is_rejected() {
        let json = r#"{"jsonrpc":"2.0","result":1,"error":{"code":-32603,"message":"x"},"id":1}"#;
        assert!(serde_json::from_str::<RpcResponse>(json).is_err());
    }

    #[test]
    fn response_with_neither_result_nor_error_is_rejected() {
        let json = r#"{"jsonrpc":"2.0","id":1}"#;
        assert!(serde_json::from_str::<RpcResponse>(json).is_err());
    }

    #[test]
    fn request_with_a_non_2_0_version_is_rejected() {
        let json = r#"{"jsonrpc":"1.0","method":"limits.sasl","id":1}"#;
        assert!(serde_json::from_str::<RpcRequest>(json).is_err());
    }

    #[test]
    fn request_with_a_missing_version_defaults_to_2_0() {
        // Documents real, verified behaviour, not necessarily desirable on its own: `jsonrpc` is
        // `#[serde(default)]` in json_rpc_types, and `Version::default()` is `V2` - so an absent
        // member is accepted as valid 2.0 rather than rejected, even though the spec requires
        // the member. This is only reachable via the control socket, which is already
        // owner-only, so a lenient default here doesn't grant anything a connection couldn't
        // already do.
        let json = r#"{"method":"limits.sasl","id":1}"#;
        assert!(serde_json::from_str::<RpcRequest>(json).is_ok());
    }
}
