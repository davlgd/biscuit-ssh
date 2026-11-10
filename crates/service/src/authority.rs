//! The authority a service acts for: token verification, certificate
//! signing, and revocations.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, ensure};
use biscuit_ssh_ca::CertificateAuthority;
use biscuit_ssh_core::{PublicKey, RevocationList, Verifier};

use crate::{RevocationSource, UnreadableRevocations};

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

    /// Fails if the revocation list is unreadable, which would refuse every
    /// request.
    pub fn check_revocations(&self) -> anyhow::Result<()> {
        self.revocations.check()
    }
}
