use biscuit_auth::error::Token as TokenError;

/// Why a request or a token was rejected.
///
/// Every variant means "deny": callers must never grant access on error.
///
/// Messages of [`Error::Denied`], [`Error::InvalidToken`] and
/// [`Error::Datalog`] can quote Datalog written by the token holder, which
/// may carry arbitrary data: services should log and return [`Error::kind`]
/// only, and show full messages to people handling their own tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A request field or command-line value is malformed.
    #[error("invalid {field}: {reason}")]
    InvalidInput {
        /// What was malformed.
        field: &'static str,
        /// Why it was refused.
        reason: &'static str,
    },

    /// The token cannot be decoded or its signatures do not match the root key.
    #[error("invalid token: {0}")]
    InvalidToken(#[source] TokenError),

    /// One of the token's blocks carries a revoked identifier.
    #[error("token revoked: {0}")]
    Revoked(String),

    /// The token is valid but its checks or the verifier policies refuse the request.
    #[error("access denied: {0}")]
    Denied(#[source] TokenError),
    /// The evaluation ran out of time. That may come from the load, and the
    /// request may then succeed when retried; a costly token can also time
    /// out every time. Access is refused meanwhile.
    #[error("token evaluation timed out")]
    Overloaded,

    /// Datalog could not be built (bad operator policy, internal error).
    #[error("datalog error: {0}")]
    Datalog(#[source] TokenError),
}

impl Error {
    /// A stable, content-free label for logs and client responses.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::InvalidInput { .. } => "invalid_input",
            Self::InvalidToken(_) => "invalid_token",
            Self::Revoked(_) => "revoked",
            Self::Denied(_) => "denied",
            Self::Overloaded => "overloaded",
            Self::Datalog(_) => "datalog",
        }
    }

    pub(crate) fn invalid(field: &'static str, reason: &'static str) -> Self {
        Self::InvalidInput { field, reason }
    }
}
