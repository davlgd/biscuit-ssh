//! Configuration file (TOML).
//!
//! ```toml
//! listen = "0.0.0.0:2200"
//! # The bastion's own SSH host key (`ssh-keygen -t ed25519 -f bastion_host_key`).
//! host_key = "/etc/biscuit-ssh/bastion_host_key"
//! root_public_key = "ed25519/..."
//! ca_key = "/etc/biscuit-ssh/ca"
//! revocation_list = "/etc/biscuit-ssh/revoked"
//! # Optional, defaults shown.
//! session_check_interval = 30  # seconds between token re-evaluations, 5 to 600
//! clock_skew = 30
//! policy = 'allow if server($s), user($u), right($s, $u);'
//!
//! # Servers reachable through the bastion, by the name tokens use.
//! [targets.web-1]
//! address = "10.0.0.5:22"
//! host_key = "ssh-ed25519 AAAA..."   # the server's host public key
//! # Optional: the bastion's address as this server sees it, when network
//! # address translation hides the local one (certificates are pinned to it).
//! source_address = "192.0.2.1"
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, ensure};
use biscuit_ssh_core::{MAX_LIFETIME, Name};
use biscuit_ssh_service::{Authority, AuthoritySettings, DEFAULT_CLOCK_SKEW, default_policy};
use russh::keys::{PrivateKey, PublicKey};
use serde::Deserialize;

/// Shortest accepted `session_check_interval`: renewals start a few seconds
/// before each lease ends.
const MIN_CHECK_INTERVAL: u64 = 5;

/// Bastion configuration, see the module documentation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to listen on.
    pub listen: SocketAddr,
    host_key: PathBuf,
    root_public_key: String,
    ca_key: PathBuf,
    revocation_list: Option<PathBuf>,
    #[serde(default = "default_check_interval")]
    session_check_interval: u64,
    #[serde(default = "default_clock_skew")]
    clock_skew: u64,
    #[serde(default = "default_policy")]
    policy: String,
    targets: HashMap<String, TargetConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetConfig {
    address: SocketAddr,
    host_key: String,
    source_address: Option<IpAddr>,
}

/// A server reachable through the bastion.
#[derive(Debug, Clone)]
pub struct Target {
    /// Where its sshd listens.
    pub address: SocketAddr,
    /// Its host key: connections presenting another key are refused.
    pub host_key: PublicKey,
    /// The bastion's address as the target sees it, when address
    /// translation hides the local one.
    pub source_address: Option<IpAddr>,
}

/// Everything the bastion needs, validated and loaded.
pub struct Settings {
    /// Signs target certificates and verifies tokens.
    pub authority: Authority,
    /// The bastion's host key.
    pub host_key: PrivateKey,
    /// Reachable servers, by name.
    pub targets: HashMap<Name, Target>,
    /// Lifetime of each lease: how often tokens are re-evaluated.
    pub check_interval: Duration,
}

fn default_check_interval() -> u64 {
    30
}

fn default_clock_skew() -> u64 {
    DEFAULT_CLOCK_SKEW
}

impl Config {
    /// Reads and parses `path`.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("invalid configuration {}", path.display()))
    }

    /// Validates the settings and loads the keys they point to.
    pub fn settings(&self) -> anyhow::Result<Settings> {
        ensure!(
            (MIN_CHECK_INTERVAL..=MAX_LIFETIME.as_secs()).contains(&self.session_check_interval),
            "session_check_interval must be between {MIN_CHECK_INTERVAL} and {} seconds",
            MAX_LIFETIME.as_secs()
        );
        let targets = self
            .targets
            .iter()
            .map(|(name, target)| {
                let name: Name = name.parse().with_context(|| format!("invalid target name {name}"))?;
                let host_key = PublicKey::from_openssh(&target.host_key)
                    .with_context(|| format!("invalid host_key for target {name}"))?;
                Ok((
                    name,
                    Target {
                        address: target.address,
                        host_key,
                        source_address: target.source_address,
                    },
                ))
            })
            .collect::<anyhow::Result<_>>()?;
        let authority = Authority::load(&AuthoritySettings {
            root_public_key: &self.root_public_key,
            ca_key: &self.ca_key,
            revocation_list: self.revocation_list.as_deref(),
            policy: &self.policy,
            clock_skew: self.clock_skew,
        })?;
        let host_key = PrivateKey::read_openssh_file(&self.host_key)
            .with_context(|| format!("cannot load host key {}", self.host_key.display()))?;
        Ok(Settings {
            authority,
            host_key,
            targets,
            check_interval: Duration::from_secs(self.session_check_interval),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
        listen = "127.0.0.1:2200"
        host_key = "/nonexistent"
        root_public_key = "ed25519/00"
        ca_key = "/nonexistent"
    "#;

    #[test]
    fn parses_targets() {
        let config: Config = toml::from_str(&format!(
            "{BASE}[targets.web-1]\naddress = \"10.0.0.5:22\"\nhost_key = \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJbfEbwogYrnFFme1Sl6w1JQERLXBMdGiwr6LsfC+Jdj\"\n"
        ))
        .unwrap();
        assert_eq!(config.session_check_interval, 30);
        assert_eq!(config.targets["web-1"].address, "10.0.0.5:22".parse().unwrap());
    }

    #[test]
    fn rejects_bad_values() {
        assert!(toml::from_str::<Config>(&format!("{BASE}targets = {{}}\nextra = 1")).is_err());
        for (extra, error) in [
            ("session_check_interval = 4\ntargets = {}", "session_check_interval"),
            ("session_check_interval = 601\ntargets = {}", "session_check_interval"),
            (
                "[targets.\"web:1\"]\naddress = \"10.0.0.5:22\"\nhost_key = \"ssh-ed25519 AAAA\"",
                "invalid target name",
            ),
            (
                "[targets.web-1]\naddress = \"10.0.0.5:22\"\nhost_key = \"garbage\"",
                "invalid host_key",
            ),
        ] {
            let config: Config = toml::from_str(&format!("{BASE}{extra}")).unwrap();
            let message = format!("{:#}", config.settings().err().unwrap());
            assert!(message.contains(error), "{extra}: {message}");
        }
    }
}
