//! biscuit-ssh bastion: an SSH server that checks Biscuit tokens and relays
//! sessions to servers only it can reach, cutting them as soon as the token
//! stops allowing access.
//!
//! Audit events are logged to stderr; set `RUST_LOG` to change verbosity.

#![warn(missing_docs)]

mod access;
mod config;
mod container;
mod relay;
mod server;
mod target;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use std::net::IpAddr;

use clap::Parser;
use russh::{MethodKind, MethodSet};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::access::Cutter;
use crate::config::{Config, Settings};
use crate::server::Connection;

#[derive(Parser)]
#[command(version, about = "SSH bastion checking Biscuit tokens")]
struct Args {
    /// Configuration file.
    #[arg(short, long, default_value = "/etc/biscuit-ssh/bastion.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    biscuit_ssh_service::init_tracing();
    let args = Args::parse();
    let config = Config::load(&args.config)?;
    let settings = Arc::new(config.settings().await?);

    let ssh = Arc::new(russh::server::Config {
        keys: vec![settings.host_key.clone()],
        methods: MethodSet::from(&[MethodKind::PublicKey, MethodKind::KeyboardInteractive][..]),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        max_auth_attempts: 6,
        keepalive_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    let admission = Arc::new(Semaphore::new(
        std::thread::available_parallelism().map_or(1, |n| n.get()),
    ));
    let listener = TcpListener::bind(config.listen).await?;
    // Clients verify it on first connection: operators hand it out.
    let host_key = settings.host_key.public_key().fingerprint(russh::keys::HashAlg::Sha256);
    tracing::info!(
        listen = %config.listen,
        servers = settings.servers.len(),
        containers = settings.containers.is_some(),
        %host_key,
        "listening"
    );

    let shutdown = biscuit_ssh_service::shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::warn!(error = %error, "cannot accept a connection");
                    continue;
                }
            },
            () = &mut shutdown => return Ok(()),
        };
        let (settings, ssh, admission) = (Arc::clone(&settings), Arc::clone(&ssh), Arc::clone(&admission));
        tokio::spawn(async move {
            if let Err(error) = serve(settings, ssh, admission, stream, peer.ip()).await {
                tracing::debug!(%peer, error = %error, "connection ended with an error");
            }
        });
    }
}

/// Runs the SSH session of one client.
async fn serve(
    settings: Arc<Settings>,
    ssh: Arc<russh::server::Config>,
    admission: Arc<Semaphore>,
    stream: TcpStream,
    peer: IpAddr,
) -> anyhow::Result<()> {
    // A duplicate of the socket lets a cut close it whatever the state of
    // the SSH session.
    let socket = stream.into_std()?;
    let cutter = Cutter::new(socket.try_clone()?);
    let stream = TcpStream::from_std(socket)?;
    let connection = Connection::new(settings, admission, peer, cutter);
    russh::server::run_stream(ssh, stream, connection).await?.await?;
    Ok(())
}
