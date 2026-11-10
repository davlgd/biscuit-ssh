//! biscuit-ssh certificate issuer: an HTTP service exchanging Biscuit tokens
//! for short-lived OpenSSH user certificates.
//!
//! Audit events are logged to stderr; set `RUST_LOG` to change verbosity.

#![warn(missing_docs)]

mod config;
mod http;
mod issue;

use std::path::PathBuf;

use clap::Parser;

use crate::config::Config;

#[derive(Parser)]
#[command(version, about = "Exchanges Biscuit tokens for short-lived OpenSSH certificates")]
struct Args {
    /// Configuration file.
    #[arg(short, long, default_value = "/etc/biscuit-ssh/issuer.toml")]
    config: PathBuf,
    /// Check the configuration, the keys, the revocation list, and the TLS
    /// certificate, then exit without listening.
    #[arg(long)]
    check: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    biscuit_ssh_service::init_tracing();

    let args = Args::parse();
    let config = Config::load(&args.config)?;
    let issuer = config.issuer()?;
    if args.check {
        issuer.authority.check_revocations()?;
        if let Some(tls) = &config.tls {
            biscuit_ssh_service::http::load_tls(tls).await?;
        }
        let tls = if config.tls.is_some() { "TLS" } else { "plain HTTP" };
        println!("{}: valid, {tls}", args.config.display());
        return Ok(());
    }
    let app = http::router(issuer, &config.trusted_proxies);
    biscuit_ssh_service::http::serve(app, config.listen, config.tls.as_ref()).await
}
