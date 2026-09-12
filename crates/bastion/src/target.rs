//! Connections from the bastion to target servers.
//!
//! Each authenticated client connection gets its own target connection,
//! authenticated with a fresh key and a certificate valid only for that
//! login, pinned to the bastion's address and carrying the client's
//! principal: target servers need nothing more than trusting the CA.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, bail, ensure};
use russh::client::{self, AuthResult};
use russh::keys::{Certificate, PrivateKey, PublicKey, PublicKeyOrCertificate};
use ssh_key::LineEnding;
use ssh_key::rand_core::OsRng;
use tokio::net::TcpStream;

use crate::access::Grant;
use crate::config::Settings;

/// Bounds connecting to a target, including the SSH handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Lifetime of the certificate the bastion logs in with: only checked at
/// login, the session is then governed by the client's lease.
const LOGIN_LIFETIME: Duration = Duration::from_secs(60);

/// A connection to a target server.
pub type TargetConnection = client::Handle<TargetHost>;

/// Accepts exactly the configured host key.
pub struct TargetHost {
    host_key: PublicKey,
}

impl client::Handler for TargetHost {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.key_data() == self.host_key.key_data(),
            PublicKeyOrCertificate::Certificate(_) => false,
        })
    }
}

/// Connects to the target of `grant` and logs in as its user.
pub async fn connect(settings: Arc<Settings>, grant: Arc<Grant>) -> anyhow::Result<TargetConnection> {
    tokio::time::timeout(CONNECT_TIMEOUT, connect_inner(settings, grant))
        .await
        .context("connection to the target timed out")?
}

async fn connect_inner(settings: Arc<Settings>, grant: Arc<Grant>) -> anyhow::Result<TargetConnection> {
    let stream = TcpStream::connect(grant.target.address)
        .await
        .with_context(|| format!("cannot connect to {}", grant.target.address))?;
    // The address the target sees, which the certificate is pinned to.
    let bastion_ip = stream.local_addr()?.ip();

    let (key, certificate) = {
        let (settings, grant) = (Arc::clone(&settings), Arc::clone(&grant));
        tokio::task::spawn_blocking(move || login_credentials(&settings, &grant, bastion_ip)).await??
    };

    let config = Arc::new(client::Config::default());
    let host = TargetHost {
        host_key: grant.target.host_key.clone(),
    };
    let mut connection = client::connect_stream(config, stream, host)
        .await
        .context("SSH handshake with the target failed (unexpected host key?)")?;
    let user = grant.request.user.as_str();
    match connection
        .authenticate_openssh_cert(user, Arc::new(key), certificate)
        .await?
    {
        AuthResult::Success => Ok(connection),
        AuthResult::Failure { .. } => bail!("the target refused the bastion certificate"),
    }
}

/// A fresh key and its certificate for logging in to the target, from a
/// fresh authorization of the client's token.
///
/// Keys and certificates come from `ssh-key` 0.6 (through the CA) and go to
/// russh, which uses 0.7: they cross over in OpenSSH format.
fn login_credentials(
    settings: &Settings,
    grant: &Grant,
    bastion_ip: std::net::IpAddr,
) -> anyhow::Result<(PrivateKey, Certificate)> {
    let authorization = grant
        .authorize(settings, SystemTime::now(), LOGIN_LIFETIME)
        .map_err(|refusal| anyhow::anyhow!("token refused: {}", refusal.kind()))?;
    let key = ssh_key::PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519)?;
    let certificate = settings.authority.ca.sign_relayed(
        key.public_key(),
        &authorization,
        bastion_ip,
        settings.authority.clock_skew,
    )?;

    let russh_key = PrivateKey::from_openssh(key.to_openssh(LineEnding::LF)?.as_bytes())?;
    let russh_certificate = Certificate::from_openssh(&certificate.to_openssh()?)?;
    ensure!(
        russh_certificate.public_key() == russh_key.public_key().key_data(),
        "certificate conversion changed its key"
    );
    Ok((russh_key, russh_certificate))
}
