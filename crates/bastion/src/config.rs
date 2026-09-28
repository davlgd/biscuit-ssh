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
//!
//! # Optional: containers reachable through Docker, by container name.
//! [containers]
//! # A root key of their own: tokens it signs reach containers only, and
//! # tokens signed by the main root key never reach containers.
//! root_public_key = "ed25519/..."
//! revocation_list = "/var/lib/biscuit-ssh/containers.revoked"
//! label = "biscuit-ssh.sandbox"   # only containers carrying this label
//! socket = "/var/run/docker.sock" # default
//! ```

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, ensure};
use biscuit_ssh_core::{MAX_LIFETIME, Name, Verifier};
use biscuit_ssh_service::{Authority, AuthoritySettings, RevocationSource, default_clock_skew, default_policy};
use bollard::{API_DEFAULT_VERSION, Docker};
use russh::keys::{PrivateKey, PublicKey};
use serde::Deserialize;

/// Shortest accepted `session_check_interval`: renewals start a few seconds
/// before each lease ends.
const MIN_CHECK_INTERVAL: u64 = 5;

/// Bounds each Docker API request, in seconds (streams are not affected).
const DOCKER_TIMEOUT: u64 = 30;

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
    #[serde(default)]
    targets: HashMap<String, TargetConfig>,
    containers: Option<ContainersConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContainersConfig {
    root_public_key: String,
    revocation_list: PathBuf,
    label: String,
    #[serde(default = "default_socket")]
    socket: PathBuf,
    #[serde(default = "default_policy")]
    policy: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetConfig {
    address: SocketAddr,
    host_key: String,
    source_address: Option<IpAddr>,
}

/// A server reachable through the bastion over SSH.
#[derive(Debug, Clone)]
pub struct Server {
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
    pub servers: HashMap<Name, Server>,
    /// Reachable containers, when enabled.
    pub containers: Option<Containers>,
    /// Lifetime of each lease: how often tokens are re-evaluated.
    pub check_interval: Duration,
}

/// Containers reachable through the Docker Engine API.
pub struct Containers {
    /// Verifies tokens for containers, with their own root key.
    pub verifier: Verifier,
    /// Revoked container tokens.
    pub revocations: RevocationSource,
    /// Label a container must carry to be reachable.
    pub label: String,
    /// The Docker Engine API.
    pub docker: Docker,
}

fn default_check_interval() -> u64 {
    30
}

fn default_socket() -> PathBuf {
    PathBuf::from("/var/run/docker.sock")
}

impl Config {
    /// Reads and parses `path`.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("invalid configuration {}", path.display()))
    }

    /// Validates the settings, loads the keys they point to, and connects to
    /// Docker when containers are enabled.
    pub async fn settings(&self) -> anyhow::Result<Settings> {
        ensure!(
            (MIN_CHECK_INTERVAL..=MAX_LIFETIME.as_secs()).contains(&self.session_check_interval),
            "session_check_interval must be between {MIN_CHECK_INTERVAL} and {} seconds",
            MAX_LIFETIME.as_secs()
        );
        let servers = self
            .targets
            .iter()
            .map(|(name, target)| {
                let name: Name = name.parse().with_context(|| format!("invalid target name {name}"))?;
                let host_key = PublicKey::from_openssh(&target.host_key)
                    .with_context(|| format!("invalid host_key for target {name}"))?;
                Ok((
                    name,
                    Server {
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
        let containers = match &self.containers {
            Some(containers) => Some(containers.connect().await?),
            None => None,
        };
        Ok(Settings {
            authority,
            host_key,
            servers,
            containers,
            check_interval: Duration::from_secs(self.session_check_interval),
        })
    }
}

impl ContainersConfig {
    async fn connect(&self) -> anyhow::Result<Containers> {
        let root_key: biscuit_ssh_core::PublicKey = self
            .root_public_key
            .parse()
            .context("invalid containers.root_public_key")?;
        ensure!(!self.label.is_empty(), "containers.label must not be empty");
        let socket = self.socket.to_str().context("containers.socket must be UTF-8")?;
        let docker = Docker::connect_with_unix(socket, DOCKER_TIMEOUT, API_DEFAULT_VERSION)
            .with_context(|| format!("cannot use Docker at {socket}"))?;
        // Speak the daemon's API version, which may be older than bollard's.
        let docker = docker
            .negotiate_version()
            .await
            .with_context(|| format!("cannot reach Docker at {socket}"))?;
        Ok(Containers {
            verifier: Verifier::new(root_key, &self.policy).context("invalid containers.policy")?,
            revocations: RevocationSource::new(Some(self.revocation_list.clone())),
            label: self.label.clone(),
            docker,
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
    fn requires_a_complete_containers_section() {
        let with = |section: &str| toml::from_str::<Config>(&format!("{BASE}targets = {{}}\n[containers]\n{section}"));
        assert!(with("root_public_key = \"ed25519/00\"\nrevocation_list = \"/r\"\nlabel = \"l\"").is_ok());
        for missing in [
            "revocation_list = \"/r\"\nlabel = \"l\"",
            "root_public_key = \"ed25519/00\"\nlabel = \"l\"",
            "root_public_key = \"ed25519/00\"\nrevocation_list = \"/r\"",
        ] {
            assert!(with(missing).is_err(), "{missing}");
        }
    }

    #[tokio::test]
    async fn rejects_bad_values() {
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
            let message = format!("{:#}", config.settings().await.err().unwrap());
            assert!(message.contains(error), "{extra}: {message}");
        }
    }
}
