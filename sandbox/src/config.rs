//! Configuration file (TOML).
//!
//! ```toml
//! listen = "0.0.0.0:8444"
//! # Clients allowed to use the API, by address; every other one gets 401.
//! allowed_clients = ["203.0.113.7"]
//! # Root key signing sandbox tokens (`biscuit-ssh admin keygen`): the
//! # bastion's [containers] root_public_key, distinct from the main root key.
//! signing_key = "/etc/biscuit-ssh/sandbox.key"
//! state_dir = "/var/lib/biscuit-ssh-sandbox"
//! # Written by the sandbox, read by the bastion's [containers] section.
//! revocation_list = "/var/lib/biscuit-ssh-sandbox/revoked"
//! # Optional, defaults shown.
//! label = "biscuit-ssh.sandbox"  # the bastion's [containers] label
//! account = "root"               # account sessions run as
//! socket = "/var/run/docker.sock"
//!
//! [bastion]
//! address = "bastion.example.com:2200"
//! # Its host public key (the bastion's host key `.pub`), for clients.
//! host_key = "ssh-ed25519 AAAA..."
//!
//! # Optional, defaults shown.
//! [limits]
//! lifetime = 3600                # longest token and sandbox life, in seconds
//! max_sandboxes = 5
//! max_creations = 2              # creations in progress at once
//! memory_mb = 512
//! cpus = 1.0
//! pids = 256
//! pull_timeout = 300             # seconds
//! # disk_mb = 2048               # writable layer size; needs overlay2 on XFS
//! #                              # with project quotas, unbounded otherwise
//!
//! [tls]
//! certificate = "/etc/biscuit-ssh/tls.crt"
//! key = "/etc/biscuit-ssh/tls.key"
//! ```

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, ensure};
use biscuit_ssh_core::{KeyPair, Name, PrivateKey};
use biscuit_ssh_service::http::Tls;
use serde::Deserialize;
use ssh_key::{HashAlg, PublicKey};

use crate::docker::Limits;

/// Shortest `limits.lifetime` accepted.
const MIN_LIFETIME: u64 = 60;

/// Longest `limits.lifetime` accepted: one hour.
pub const MAX_LIFETIME: u64 = 3600;

/// Sandbox service configuration, see the module documentation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to listen on.
    pub listen: SocketAddr,
    /// TLS certificate and key.
    pub tls: Option<Tls>,
    allowed_clients: Vec<IpAddr>,
    signing_key: PathBuf,
    /// Directory of the state file and lock.
    pub state_dir: PathBuf,
    /// Revocation list written for the bastion.
    pub revocation_list: PathBuf,
    bastion: BastionConfig,
    #[serde(default = "default_label")]
    label: String,
    #[serde(default = "default_account")]
    account: String,
    #[serde(default = "default_socket")]
    /// Docker socket.
    pub socket: PathBuf,
    #[serde(default)]
    limits: LimitsConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BastionConfig {
    address: String,
    host_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct LimitsConfig {
    lifetime: u64,
    max_sandboxes: usize,
    max_creations: usize,
    memory_mb: i64,
    cpus: f64,
    pids: i64,
    pull_timeout: u64,
    disk_mb: Option<u64>,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            lifetime: MAX_LIFETIME,
            max_sandboxes: 5,
            max_creations: 2,
            memory_mb: 512,
            cpus: 1.0,
            pids: 256,
            pull_timeout: 300,
            disk_mb: None,
        }
    }
}

/// How clients reach sandboxes, for the responses.
#[derive(Debug, Clone)]
pub struct Bastion {
    /// `host:port`.
    pub address: String,
    /// Host key fingerprint, `SHA256:…`.
    pub fingerprint: String,
    /// Its `known_hosts` line.
    pub known_hosts: String,
}

impl Bastion {
    fn new(address: &str, host_key: &str) -> anyhow::Result<Self> {
        let key =
            PublicKey::from_openssh(host_key).context("invalid bastion.host_key: expected an OpenSSH public key")?;
        let (host, port) = address.rsplit_once(':').context("bastion.address must be host:port")?;
        let port: u16 = port.parse().context("bastion.address must be host:port")?;
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let key = PublicKey::new(key.key_data().clone(), "");
        let line = key.to_openssh().context("invalid bastion.host_key")?;
        let known_hosts = match port {
            22 => format!("{host} {line}"),
            _ => format!("[{host}]:{port} {line}"),
        };
        Ok(Self {
            address: address.to_owned(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            known_hosts,
        })
    }
}

/// Everything the service needs, validated and loaded.
pub struct Settings {
    /// Clients allowed to use the API.
    pub allowed_clients: Vec<IpAddr>,
    /// Signs sandbox tokens.
    pub signing_key: KeyPair,
    /// Label key marking the containers of the service.
    pub label: String,
    /// Account sessions run as.
    pub account: Name,
    /// How clients reach sandboxes.
    pub bastion: Bastion,
    /// Longest (and default) sandbox life, in seconds.
    pub lifetime: u64,
    /// Most sandboxes at once, being created included.
    pub max_sandboxes: usize,
    /// Most creations in progress at once.
    pub max_creations: usize,
    /// Per-container limits.
    pub limits: Limits,
    /// Longest image pull.
    pub pull_timeout: Duration,
}

fn default_label() -> String {
    "biscuit-ssh.sandbox".to_owned()
}

fn default_account() -> String {
    "root".to_owned()
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

    /// Validates the settings and loads the signing key.
    pub fn settings(&self) -> anyhow::Result<Settings> {
        let limits = &self.limits;
        ensure!(!self.allowed_clients.is_empty(), "allowed_clients must not be empty");
        ensure!(
            (MIN_LIFETIME..=MAX_LIFETIME).contains(&limits.lifetime),
            "limits.lifetime must be between {MIN_LIFETIME} and {MAX_LIFETIME} seconds"
        );
        ensure!(
            limits.max_sandboxes > 0 && limits.max_creations > 0,
            "limits must be positive"
        );
        ensure!(limits.memory_mb > 0 && limits.pids > 0, "limits must be positive");
        ensure!(
            limits.cpus.is_finite() && limits.cpus > 0.0 && limits.cpus <= 1024.0,
            "limits.cpus must be between 0 and 1024"
        );
        // Whole billionths of a CPU; the fraction is dropped on purpose.
        let nano_cpus = (limits.cpus * 1e9) as i64;
        ensure!(nano_cpus > 0, "limits.cpus must be between 0 and 1024");
        let memory = limits
            .memory_mb
            .checked_mul(1024 * 1024)
            .context("limits.memory_mb is too large")?;
        ensure!(!self.label.is_empty(), "label must not be empty");
        let text = std::fs::read_to_string(&self.signing_key)
            .with_context(|| format!("cannot read {}", self.signing_key.display()))?;
        let key: PrivateKey = text.trim().parse().context("invalid signing_key")?;
        Ok(Settings {
            allowed_clients: self.allowed_clients.iter().map(IpAddr::to_canonical).collect(),
            signing_key: KeyPair::from(&key),
            label: self.label.clone(),
            account: self.account.parse().context("invalid account")?,
            bastion: Bastion::new(&self.bastion.address, &self.bastion.host_key)?,
            lifetime: limits.lifetime,
            max_sandboxes: limits.max_sandboxes,
            max_creations: limits.max_creations,
            limits: Limits {
                memory,
                nano_cpus,
                pids: limits.pids,
                disk: limits.disk_mb.map(|mb| format!("{mb}M")),
            },
            pull_timeout: Duration::from_secs(limits.pull_timeout),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
        listen = "127.0.0.1:8444"
        allowed_clients = ["192.0.2.7"]
        signing_key = "/nonexistent"
        state_dir = "/tmp/state"
        revocation_list = "/tmp/revoked"
        [bastion]
        address = "bastion.example.com:2200"
        host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJbfEbwogYrnFFme1Sl6w1JQERLXBMdGiwr6LsfC+Jdj comment"
    "#;

    #[test]
    fn parses_with_defaults() {
        let config: Config = toml::from_str(BASE).unwrap();
        assert_eq!(config.limits.lifetime, MAX_LIFETIME);
        assert_eq!(config.label, "biscuit-ssh.sandbox");
        assert_eq!(config.account, "root");
    }

    #[test]
    fn derives_the_bastion_host_key_forms() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJbfEbwogYrnFFme1Sl6w1JQERLXBMdGiwr6LsfC+Jdj";
        let bastion = Bastion::new("bastion.example.com:2200", &format!("{key} comment")).unwrap();
        assert!(bastion.fingerprint.starts_with("SHA256:"));
        assert_eq!(bastion.known_hosts, format!("[bastion.example.com]:2200 {key}"));
        let bastion = Bastion::new("[2001:db8::1]:22", key).unwrap();
        assert_eq!(bastion.known_hosts, format!("2001:db8::1 {key}"));
        assert!(Bastion::new("bastion.example.com:2200", "SHA256:x").is_err());
    }

    #[test]
    fn rejects_unknown_fields_and_bad_limits() {
        assert!(toml::from_str::<Config>(&format!("{BASE}extra = 1")).is_err());
        for limits in [
            "lifetime = 59",
            "lifetime = 3601",
            "max_sandboxes = 0",
            "cpus = 0.0",
            "cpus = inf",
            "cpus = 1e-12",
            "memory_mb = 9223372036854775807",
        ] {
            let config: Config = toml::from_str(&format!("{BASE}[limits]\n{limits}")).unwrap();
            let error = config.settings().err().unwrap().to_string();
            assert!(error.contains("limits"), "{limits}: {error}");
        }
    }
}
