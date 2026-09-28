//! Plumbing shared by the biscuit-ssh services (issuer and bastion): the
//! authority they act for (token verification, certificate signing,
//! revocations), logging and shutdown.

#![warn(missing_docs)]

#[cfg(feature = "http")]
pub mod http;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, ensure};
use biscuit_ssh_ca::CertificateAuthority;
use biscuit_ssh_core::{DEFAULT_POLICY, PublicKey, RevocationList, Verifier};
use tracing_subscriber::EnvFilter;

/// The default `clock_skew`, in seconds, for configuration defaults.
pub fn default_clock_skew() -> u64 {
    30
}

/// Longest accepted `clock_skew`.
const MAX_CLOCK_SKEW: Duration = Duration::from_secs(300);

/// The authority settings every service configuration carries.
#[derive(Debug)]
pub struct AuthoritySettings<'a> {
    /// Biscuit root public key, `ed25519/...`.
    pub root_public_key: &'a str,
    /// Unencrypted OpenSSH CA private key, mode 600.
    pub ca_key: &'a Path,
    /// Revoked block identifiers, re-read on each use.
    pub revocation_list: Option<&'a Path>,
    /// Datalog verifier policies.
    pub policy: &'a str,
    /// Seconds certificates are backdated, for servers with a lagging clock.
    pub clock_skew: u64,
}

/// Verifies tokens and signs certificates for a service.
pub struct Authority {
    /// Token verifier.
    pub verifier: Verifier,
    /// Certificate signer.
    pub ca: CertificateAuthority,
    /// See [`AuthoritySettings::clock_skew`].
    pub clock_skew: Duration,
    revocations: RevocationSource,
}

impl Authority {
    /// Validates `settings` and loads the keys they point to.
    pub fn load(settings: &AuthoritySettings) -> anyhow::Result<Self> {
        let clock_skew = Duration::from_secs(settings.clock_skew);
        ensure!(
            clock_skew <= MAX_CLOCK_SKEW,
            "clock_skew must be at most {} seconds",
            MAX_CLOCK_SKEW.as_secs()
        );
        let root_key: PublicKey = settings.root_public_key.parse().context("invalid root_public_key")?;
        Ok(Self::new(
            Verifier::new(root_key, settings.policy).context("invalid policy")?,
            CertificateAuthority::load(settings.ca_key)?,
            settings.revocation_list.map(Path::to_path_buf),
            clock_skew,
        ))
    }

    /// Assembles an authority from loaded parts, e.g. in tests.
    pub fn new(
        verifier: Verifier,
        ca: CertificateAuthority,
        revocation_list: Option<PathBuf>,
        clock_skew: Duration,
    ) -> Self {
        Self {
            verifier,
            ca,
            clock_skew,
            revocations: RevocationSource::new(revocation_list),
        }
    }

    /// The current revocation list, see [`RevocationSource::read`].
    pub fn revocations(&self) -> Result<RevocationList, UnreadableRevocations> {
        self.revocations.read()
    }
}

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
