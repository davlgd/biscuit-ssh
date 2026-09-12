//! biscuit-ssh certificate issuer: an HTTP service exchanging Biscuit tokens
//! for short-lived OpenSSH user certificates.
//!
//! Audit events are logged to stderr; set `RUST_LOG` to change verbosity.

#![warn(missing_docs)]

mod config;
mod http;
mod issue;

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::config::Config;

/// How long open connections may take to finish on shutdown.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(version, about = "Exchanges Biscuit tokens for short-lived OpenSSH certificates")]
struct Args {
    /// Configuration file.
    #[arg(short, long, default_value = "/etc/biscuit-ssh/issuer.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        // No color codes in journald or log files.
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    let args = Args::parse();
    let config = Config::load(&args.config)?;
    let app =
        http::router(config.issuer()?, &config.trusted_proxies).into_make_service_with_connect_info::<SocketAddr>();

    let handle = Handle::new();
    tokio::spawn(shutdown_on_signal(handle.clone()));

    match &config.tls {
        Some(tls) => {
            // Both rustls providers may be compiled in through dependencies;
            // pick one explicitly. Failure only means one is already set.
            let _ = rustls::crypto::ring::default_provider().install_default();
            let tls = RustlsConfig::from_pem_file(&tls.certificate, &tls.key)
                .await
                .context("cannot load TLS certificate or key")?;
            tracing::info!(listen = %config.listen, "serving over TLS");
            axum_server::bind_rustls(config.listen, tls)
                .handle(handle)
                .serve(app)
                .await?;
        }
        None => {
            tracing::warn!(listen = %config.listen, "serving plain HTTP: only use behind a TLS proxy or on loopback");
            axum_server::bind(config.listen).handle(handle).serve(app).await?;
        }
    }
    Ok(())
}

/// Stops accepting connections on SIGINT or SIGTERM.
async fn shutdown_on_signal(handle: Handle<SocketAddr>) {
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
    handle.graceful_shutdown(Some(SHUTDOWN_GRACE));
}
