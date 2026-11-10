//! Plumbing shared by the biscuit-ssh services: revocation lists, logging
//! and shutdown, plus the authority the issuer and the bastion act for
//! (token verification, certificate signing), with the `authority`
//! feature, and an HTTP API server over TLS, with the `http` feature.

#![warn(missing_docs)]

#[cfg(feature = "authority")]
mod authority;
#[cfg(feature = "http")]
pub mod http;

#[cfg(feature = "authority")]
pub use authority::{Authority, AuthoritySettings, default_clock_skew};

use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::Context;
use biscuit_ssh_core::{DEFAULT_POLICY, RevocationList};
use tracing_subscriber::EnvFilter;

/// Where a revocation list comes from: a file, or nothing (no revocation).
#[derive(Debug, Clone)]
pub struct RevocationSource(Option<PathBuf>);

impl RevocationSource {
    /// Reads `path` on each [`read`](Self::read); `None` revokes nothing.
    pub fn new(path: Option<PathBuf>) -> Self {
        Self(path)
    }

    /// The current revocation list, read again on each call so revocations
    /// apply immediately.
    ///
    /// Fails closed: an unreadable list could hide a revocation, so callers
    /// must refuse access on error. The cause is logged here.
    pub fn read(&self) -> Result<RevocationList, UnreadableRevocations> {
        let Some(path) = &self.0 else {
            return Ok(RevocationList::default());
        };
        RevocationList::load(path).map_err(|e| {
            tracing::error!(path = %path.display(), error = %e, "cannot read revocation list");
            UnreadableRevocations
        })
    }

    /// Fails, with the cause, if the list is unreadable.
    pub fn check(&self) -> anyhow::Result<()> {
        if let Some(path) = &self.0 {
            RevocationList::load(path)
                .with_context(|| format!("cannot read the revocation list {}", path.display()))?;
        }
        Ok(())
    }
}

/// The revocation list could not be read; details are in the logs.
#[derive(Debug)]
pub struct UnreadableRevocations;

/// The default Datalog verifier policies, for configuration defaults.
pub fn default_policy() -> String {
    DEFAULT_POLICY.to_owned()
}

/// Logs to stderr, at the level set by `RUST_LOG` (default `info`), with
/// colors only on a terminal (not in journald or log files).
pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
}

/// Resolves on SIGINT or SIGTERM.
pub async fn shutdown_signal() {
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = interrupt => {}
        _ = terminate => {}
    }
    tracing::info!("shutting down");
}
