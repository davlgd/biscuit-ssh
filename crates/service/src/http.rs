//! Serving an HTTP API over TLS, shared by the HTTP services.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use serde::Deserialize;

/// How long open connections may take to finish on shutdown.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// TLS certificate chain and private key files, in PEM.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    /// Certificate chain.
    pub certificate: PathBuf,
    /// Private key.
    pub key: PathBuf,
}

/// Serves `app` on `listen` until SIGINT or SIGTERM, over TLS when given;
/// handlers can read the client address through `ConnectInfo<SocketAddr>`.
///
/// Without TLS, the service must only be reached through a TLS-terminating
/// proxy or on a loopback address: a warning says so.
pub async fn serve(app: Router, listen: SocketAddr, tls: Option<&Tls>) -> anyhow::Result<()> {
    let app = app.into_make_service_with_connect_info::<SocketAddr>();
    let handle = Handle::new();
    let shutdown = handle.clone();
    tokio::spawn(async move {
        crate::shutdown_signal().await;
        shutdown.graceful_shutdown(Some(SHUTDOWN_GRACE));
    });

    match tls {
        Some(tls) => {
            let config = load_tls(tls).await?;
            tracing::info!(%listen, "serving over TLS");
            axum_server::bind_rustls(listen, config)
                .handle(handle)
                .serve(app)
                .await?;
        }
        None => {
            tracing::warn!(%listen, "serving plain HTTP: only use behind a TLS proxy or on loopback");
            axum_server::bind(listen).handle(handle).serve(app).await?;
        }
    }
    Ok(())
}

/// Loads the TLS certificate chain and key of `tls`, failing if either is
/// unreadable or they don't match.
pub async fn load_tls(tls: &Tls) -> anyhow::Result<RustlsConfig> {
    // Both rustls providers may be compiled in through dependencies; pick
    // one explicitly. Failure only means one is already set.
    let _ = rustls::crypto::ring::default_provider().install_default();
    RustlsConfig::from_pem_file(&tls.certificate, &tls.key)
        .await
        .context("cannot load TLS certificate or key")
}
