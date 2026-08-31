use std::collections::HashMap;
use std::io;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Hard cap on one request's total size; real Postfix requests are a few KB at
/// most.
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

/// One Postfix SMTP access policy delegation request.
#[derive(Debug, Clone)]
pub struct Request {
    attributes: HashMap<String, String>,
}

impl Request {
    /// Reads key=value lines up to a blank line; None if EOF precedes it.
    pub async fn read_from<R: AsyncBufRead + Unpin>(reader: &mut R) -> io::Result<Option<Request>> {
        let mut attributes = HashMap::new();
        let mut limited = reader.take(MAX_REQUEST_BYTES);
        let mut line = String::new();
        loop {
            line.clear();
            let read = limited.read_line(&mut line).await?;
            if read == 0 {
                return if limited.limit() == 0 {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "policy request exceeded max size"))
                } else {
                    Ok(None)
                };
            }
            if !line.ends_with('\n') {
                // Got bytes but no terminator: either the cap was hit mid-line, or the
                // connection closed mid-line for an unrelated reason - tell those apart
                // rather than always blaming the cap.
                return if limited.limit() == 0 {
                    Err(io::Error::new(io::ErrorKind::InvalidData, "policy request exceeded max size"))
                } else {
                    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed mid-request"))
                };
            }
            let trimmed = line.trim_end_matches(['\n', '\r']);
            if trimmed.is_empty() {
                return Ok(Some(Request { attributes }));
            }
            if let Some((key, value)) = trimmed.split_once('=') {
                attributes.insert(key.to_string(), value.to_string());
            }
        }
    }

    /// The authenticated SASL username, if the client authenticated.
    ///
    /// Postfix sends `sasl_username=` (present but empty) rather than omitting
    /// the attribute for unauthenticated sessions, so an empty value - and,
    /// trimming first, a whitespace-only one - is treated as absent.
    pub fn sasl_username(&self) -> Option<&str> {
        self.attributes.get("sasl_username").map(|s| s.trim()).filter(|s| !s.is_empty())
    }

    /// The message's final recipient count, sent at the DATA stage.
    pub fn recipient_count(&self) -> Option<u32> { self.attributes.get("recipient_count")?.parse().ok() }

    /// The restriction class this request was sent from, e.g. "DATA" or "RCPT".
    pub fn protocol_state(&self) -> Option<&str> { self.attributes.get("protocol_state").map(String::as_str) }

    /// A fixed unix timestamp for `Limiter::check` to use as "now" instead of
    /// Valkey's own TIME - not a real Postfix attribute, so parsing it is
    /// only compiled in under the integration-tests feature. Callers don't
    /// need to know which build this is: outside that feature this always
    /// returns `None`, regardless of what a client actually sent.
    pub fn now_override(&self) -> Option<u64> {
        #[cfg(feature = "integration-tests")]
        {
            self.attributes.get("now_override")?.parse().ok()
        }
        #[cfg(not(feature = "integration-tests"))]
        {
            None
        }
    }
}

/// Writes a policy response, e.g. `write_action(w, "dunno")`.
pub async fn write_action<W: AsyncWrite + Unpin>(writer: &mut W, action: &str) -> io::Result<()> {
    writer.write_all(format!("action={action}\n\n").as_bytes()).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with_sasl_username(sasl_username: &str) -> Request {
        Request { attributes: HashMap::from([("sasl_username".to_string(), sasl_username.to_string())]) }
    }

    #[test]
    fn empty_sasl_username_is_absent() {
        assert_eq!(request_with_sasl_username("").sasl_username(), None);
    }

    #[test]
    fn whitespace_only_sasl_username_is_absent() {
        assert_eq!(request_with_sasl_username("   ").sasl_username(), None);
    }

    #[test]
    fn sasl_username_is_trimmed() {
        assert_eq!(request_with_sasl_username("  alice  ").sasl_username(), Some("alice"));
    }
}
