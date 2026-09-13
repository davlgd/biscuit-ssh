//! Configuration file (TOML).
//!
//! ```toml
//! listen = "0.0.0.0:8443"
//! # Biscuit root public key, as printed by `biscuit-ssh admin keygen`.
//! root_public_key = "ed25519/..."
//! # Unencrypted OpenSSH private key, mode 600 (`ssh-keygen -t ed25519 -f ca`).
//! ca_key = "/etc/biscuit-ssh/ca"
//! # Optional: one revoked block identifier per line, re-read on each request.
//! revocation_list = "/etc/biscuit-ssh/revoked"
//! # Optional, defaults shown.
//! certificate_lifetime = 120   # seconds, at most 600
//! clock_skew = 30              # seconds certificates are backdated, at most 300
//! policy = 'allow if server($s), user($u), right($s, $u);'
//! # Optional: the proxy in front of the issuer, trusted to append the client
//! # address to X-Forwarded-For. Only the last entry is used: a single proxy.
//! trusted_proxies = ["127.0.0.1"]
//!
//! # Optional: without it the API is served over plain HTTP, which is only
//! # acceptable behind a TLS-terminating proxy or on a loopback address.
//! [tls]
//! certificate = "/etc/biscuit-ssh/tls.crt"
//! key = "/etc/biscuit-ssh/tls.key"
//! ```

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, ensure};
use biscuit_ssh_core::MAX_LIFETIME;
use biscuit_ssh_service::{Authority, AuthoritySettings, default_clock_skew, default_policy};
use serde::Deserialize;

use crate::issue::Issuer;

/// Issuer configuration, see the module documentation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to listen on.
    pub listen: SocketAddr,
    root_public_key: String,
    ca_key: PathBuf,
    revocation_list: Option<PathBuf>,
    #[serde(default = "default_lifetime")]
    certificate_lifetime: u64,
    #[serde(default = "default_clock_skew")]
    clock_skew: u64,
    #[serde(default = "default_policy")]
    policy: String,
    /// Proxies whose `X-Forwarded-For` is trusted.
    #[serde(default)]
    pub trusted_proxies: Vec<IpAddr>,
    /// TLS certificate and key, in PEM.
    pub tls: Option<Tls>,
}

/// TLS certificate chain and private key files, in PEM.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    /// Certificate chain.
    pub certificate: PathBuf,
    /// Private key.
    pub key: PathBuf,
}

fn default_lifetime() -> u64 {
    120
}

impl Config {
    /// Reads and parses `path`.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("invalid configuration {}", path.display()))
    }

    /// Validates the settings and loads the keys they point to.
    pub fn issuer(&self) -> anyhow::Result<Issuer> {
        let lifetime = Duration::from_secs(self.certificate_lifetime);
        ensure!(
            (1..=MAX_LIFETIME.as_secs()).contains(&self.certificate_lifetime),
            "certificate_lifetime must be between 1 and {} seconds",
            MAX_LIFETIME.as_secs()
        );
        let authority = Authority::load(&AuthoritySettings {
            root_public_key: &self.root_public_key,
            ca_key: &self.ca_key,
            revocation_list: self.revocation_list.as_deref(),
            policy: &self.policy,
            clock_skew: self.clock_skew,
        })?;
        Ok(Issuer { authority, lifetime })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_configuration_with_defaults() {
        let config: Config = toml::from_str(
            r#"
            listen = "127.0.0.1:8443"
            root_public_key = "ed25519/00"
            ca_key = "/nonexistent"
            "#,
        )
        .unwrap();
        assert_eq!(config.certificate_lifetime, 120);
        assert_eq!(config.clock_skew, 30);
        assert_eq!(config.policy, default_policy());
        assert!(config.tls.is_none() && config.trusted_proxies.is_empty());
    }

    #[test]
    fn rejects_unknown_fields_and_bad_values() {
        let base = "listen = \"127.0.0.1:8443\"\nroot_public_key = \"ed25519/00\"\nca_key = \"/nonexistent\"\n";
        assert!(toml::from_str::<Config>(&format!("{base}lifetim = 3")).is_err());
        for extra in [
            "certificate_lifetime = 0",
            "certificate_lifetime = 601",
            "clock_skew = 301",
        ] {
            let config: Config = toml::from_str(&format!("{base}{extra}")).unwrap();
            let error = config.issuer().err().unwrap().to_string();
            assert!(error.contains("must be"), "{extra}: {error}");
        }
    }
}
