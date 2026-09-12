//! biscuit-ssh bastion: an SSH server that checks Biscuit tokens and relays
//! sessions to servers only it can reach, cutting them as soon as the token
//! stops allowing access.
//!
//! Audit events are logged to stderr; set `RUST_LOG` to change verbosity.

#![warn(missing_docs)]

mod access;
mod config;
mod relay;
mod server;
mod target;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use russh::server::Server as _;
use russh::{MethodKind, MethodSet};
use tokio::net::TcpListener;

use crate::config::Config;
use crate::server::Bastion;

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
    let settings = config.settings()?;

    let ssh = Arc::new(russh::server::Config {
        keys: vec![settings.host_key.clone()],
        methods: MethodSet::from(&[MethodKind::PublicKey, MethodKind::KeyboardInteractive][..]),
        auth_rejection_time: Duration::from_secs(1),
        auth_rejection_time_initial: Some(Duration::ZERO),
        max_auth_attempts: 6,
        keepalive_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    let listener = TcpListener::bind(config.listen).await?;
    tracing::info!(listen = %config.listen, targets = settings.targets.len(), "listening");

    let mut bastion = Bastion {
        settings: Arc::new(settings),
    };
    let running = bastion.run_on_socket(ssh, &listener);
    let handle = running.handle();
    tokio::spawn(async move {
        biscuit_ssh_service::shutdown_signal().await;
        handle.shutdown("bastion shutting down".to_owned());
    });
    running.await?;
    Ok(())
}
