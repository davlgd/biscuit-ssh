//! biscuit-ssh-sandbox: a REST service creating disposable containers from
//! Docker Hub images, reachable by SSH only through the biscuit-ssh bastion,
//! with a Biscuit token restricted to the requesting address. A container
//! lives as long as its token: it is removed when the token expires or is
//! revoked through the API.
//!
//! Events are logged to stderr; set `RUST_LOG` to change verbosity.

#![warn(missing_docs)]

mod api;
mod config;
mod docker;
mod image;
mod lifecycle;
mod state;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use bollard::{API_DEFAULT_VERSION, Docker};
use clap::Parser;

use crate::config::Config;
use crate::lifecycle::{REAP_INTERVAL, Sandboxes, random_hex};
use crate::state::Store;

/// Bounds each Docker API request, in seconds (pull streams excepted).
const DOCKER_TIMEOUT: u64 = 60;

#[derive(Parser)]
#[command(version, about = "Disposable containers reachable through the biscuit-ssh bastion")]
struct Args {
    /// Configuration file.
    #[arg(short, long, default_value = "/etc/biscuit-ssh/sandbox.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    biscuit_ssh_service::init_tracing();
    let args = Args::parse();
    let config = Config::load(&args.config)?;
    let settings = config.settings()?;

    let socket = config.socket.to_str().context("socket must be UTF-8")?;
    let docker = Docker::connect_with_unix(socket, DOCKER_TIMEOUT, API_DEFAULT_VERSION)
        .with_context(|| format!("cannot use Docker at {socket}"))?
        // Speak the daemon's API version, which may be older than bollard's.
        .negotiate_version()
        .await
        .with_context(|| format!("cannot reach Docker at {socket}"))?;
    let store = Store::open(&config.state_dir, &config.revocation_list, random_hex)?;

    let sandboxes = Arc::new(Sandboxes::new(docker, settings, store));
    sandboxes.recover().await.context("cannot recover the previous state")?;
    let reaper = Arc::clone(&sandboxes);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(REAP_INTERVAL);
        loop {
            interval.tick().await;
            reaper.reap().await;
        }
    });

    biscuit_ssh_service::http::serve(api::router(sandboxes), config.listen, config.tls.as_ref()).await
}
