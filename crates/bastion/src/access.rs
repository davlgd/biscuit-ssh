//! What an authenticated connection may do, and for how long.
//!
//! A connection holds a lease: an authorization covering up to
//! `session_check_interval`. Shortly before it ends, the token is evaluated
//! again for the next window, starting exactly where the lease ends, so the
//! covered time is contiguous and every second the token refuses is caught.
//! The connection is cut when the token stops allowing access, at that exact
//! second, and at once if it is revoked or cannot be checked.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use biscuit_ssh_core::{AccessRequest, Authorization};
use russh::Disconnect;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::config::{Settings, Target};

/// How long before a lease ends its renewal starts.
const RENEWAL_MARGIN: u64 = 5;

/// An authenticated connection: the token presented and what it was
/// checked for.
pub struct Grant {
    /// The token, kept to evaluate it again during the connection.
    pub token: String,
    /// The request as authenticated; only its time changes afterwards.
    pub request: AccessRequest,
    /// The server connections are relayed to.
    pub target: Target,
}

/// Why a token check failed.
#[derive(Debug)]
pub enum Refusal {
    /// The token does not allow the request (at the requested time).
    Denied(biscuit_ssh_core::Error),
    /// Revoked, invalid, or the revocation list is unreadable: stop at once.
    Revoked(&'static str),
}

impl Refusal {
    /// A stable, content-free label for logs.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Denied(e) => e.kind(),
            Self::Revoked(kind) => kind,
        }
    }
}

impl Grant {
    /// Evaluates the token for `lifetime` from `time`. Blocking: Datalog.
    pub fn authorize(
        &self,
        settings: &Settings,
        time: SystemTime,
        lifetime: Duration,
    ) -> Result<Authorization, Refusal> {
        authorize(
            settings,
            &self.token,
            &AccessRequest {
                time,
                ..self.request.clone()
            },
            lifetime,
        )
    }
}

/// Checks `token` against `request` and the current revocation list.
pub fn authorize(
    settings: &Settings,
    token: &str,
    request: &AccessRequest,
    lifetime: Duration,
) -> Result<Authorization, Refusal> {
    let revoked = settings
        .authority
        .revocations()
        .map_err(|_| Refusal::Revoked("revocation_list_unreadable"))?;
    settings
        .authority
        .verifier
        .authorize(token, request, &revoked, lifetime)
        .map_err(|e| match e {
            biscuit_ssh_core::Error::Denied(_) => Refusal::Denied(e),
            _ => Refusal::Revoked(e.kind()),
        })
}

/// Keeps renewing the lease of a connection until the token stops allowing
/// it, then cuts the connection: `cut` is set, so pending requests fail, and
/// the client is disconnected.
///
/// Returns early, without cutting, once the connection is gone (every
/// receiver of `cut` dropped).
pub async fn guard(
    settings: Arc<Settings>,
    grant: Arc<Grant>,
    mut lease_end: u64,
    client: russh::server::Handle,
    cut: watch::Sender<bool>,
) {
    let reason = loop {
        let deadline = instant_at(lease_end);
        tokio::select! {
            () = tokio::time::sleep_until(instant_at(lease_end.saturating_sub(RENEWAL_MARGIN))) => {}
            () = cut.closed() => return,
        }
        let (settings, grant) = (Arc::clone(&settings), Arc::clone(&grant));
        let start = UNIX_EPOCH + Duration::from_secs(lease_end);
        let renewal = tokio::task::spawn_blocking(move || grant.authorize(&settings, start, settings.check_interval));
        tokio::select! {
            result = renewal => match result {
                Ok(Ok(authorization)) => lease_end = authorization.valid_until(),
                Ok(Err(Refusal::Denied(_))) => {
                    // Still allowed until the lease ends, not a second more.
                    tokio::select! {
                        () = tokio::time::sleep_until(deadline) => {}
                        () = cut.closed() => return,
                    }
                    break "access expired";
                }
                Ok(Err(refusal)) => break refusal.kind(),
                Err(_) => break "internal error",
            },
            () = tokio::time::sleep_until(deadline) => break "renewal too slow",
            () = cut.closed() => return,
        }
    };
    tracing::warn!(reason, "session cut");
    let _ = cut.send(true);
    let _ = client
        .disconnect(
            Disconnect::ByApplication,
            format!("biscuit-ssh: {reason}"),
            String::new(),
        )
        .await;
}

/// The instant corresponding to `seconds` since the Unix epoch, or now if
/// that is already past.
fn instant_at(seconds: u64) -> Instant {
    let at = UNIX_EPOCH + Duration::from_secs(seconds);
    Instant::now() + at.duration_since(SystemTime::now()).unwrap_or_default()
}
