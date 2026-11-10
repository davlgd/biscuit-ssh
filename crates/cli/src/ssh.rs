//! `biscuit-ssh ssh`: connects through the bastion, or with a certificate
//! from the issuer when built with the `certificates` feature.

use anyhow::Context;

use crate::bastion;
#[cfg(feature = "certificates")]
use crate::certificate;
use crate::credentials::Credentials;

#[cfg_attr(feature = "certificates", doc = "Connect with a certificate, or through a bastion")]
#[cfg_attr(not(feature = "certificates"), doc = "Connect through a bastion")]
#[doc = ""]
#[doc = "Examples:"]
#[cfg_attr(
    feature = "certificates",
    doc = "   biscuit-ssh ssh -t my.token deploy@web-1.example.com uptime"
)]
#[cfg_attr(
    feature = "certificates",
    doc = "   biscuit-ssh ssh -t my.token --server web-1 deploy@192.0.2.10 -p 2222"
)]
#[doc = "   biscuit-ssh ssh -t my.token --bastion bastion.example.com:2200 deploy@web-1"]
#[derive(Debug, clap::Args)]
#[command(verbatim_doc_comment)]
pub struct Args {
    /// Where to connect, as `user@host`, or `user@server` through a bastion.
    destination: String,
    /// Server name in the token, when it differs from the host of
    /// DESTINATION, e.g. when connecting by address [default: that host].
    #[cfg(feature = "certificates")]
    #[arg(long)]
    server: Option<String>,
    /// Connect through this bastion, `host` or `host:port`: DESTINATION is
    /// then `user@server`, with the server named as in the token.
    #[arg(long, value_name = "HOST[:PORT]")]
    #[cfg_attr(feature = "certificates", arg(conflicts_with = "server"))]
    #[cfg_attr(not(feature = "certificates"), arg(required = true))]
    bastion: Option<String>,
    #[command(flatten)]
    credentials: Credentials,
    #[cfg(feature = "certificates")]
    #[command(flatten)]
    issuer: certificate::IssuerOptions,
    /// Command to force on the session, when the token requires one: it
    /// runs whatever remote command `ssh` asks for.
    #[arg(long)]
    command: Option<String>,
    /// Passed to `ssh` after the destination, as with `ssh` itself: options
    /// (there, `-t` is ssh's own), then a remote command.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, value_name = "SSH_ARGS")]
    ssh_args: Vec<String>,
}

/// Runs `biscuit-ssh ssh`; only returns on error.
pub fn run(args: Args) -> anyhow::Result<()> {
    let (user, host) = args
        .destination
        .rsplit_once('@')
        .filter(|(user, host)| !user.is_empty() && !host.is_empty() && !user.starts_with('-'))
        .context("the destination must be user@host")?;
    let mut ssh = match &args.bastion {
        Some(bastion) => bastion::ssh_command(
            &args.credentials,
            bastion,
            (user, host),
            args.command.as_deref(),
            &args.ssh_args,
        )?,
        #[cfg(feature = "certificates")]
        None => {
            let server = args.server.as_deref().unwrap_or(host);
            let login = certificate::login(&args.credentials, &args.issuer, server, user, args.command.as_deref())?;
            certificate::ssh_command(&login, &args.destination, &args.ssh_args)?
        }
        // Without certificates, the command line requires --bastion.
        #[cfg(not(feature = "certificates"))]
        None => anyhow::bail!("--bastion is required"),
    };

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Only returns if ssh could not be started.
        Err(ssh.exec()).context("cannot run ssh")
    }
    #[cfg(not(unix))]
    {
        let status = ssh.status().context("cannot run ssh")?;
        std::process::exit(status.code().unwrap_or(255));
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: Args,
    }

    fn parse(line: &[&str]) -> Result<Args, clap::Error> {
        let argv = ["biscuit-ssh", "-t", "token"];
        Cli::try_parse_from(argv.iter().chain(line)).map(|cli| cli.args)
    }

    #[test]
    fn passes_ssh_arguments_through_after_the_destination() {
        let args = parse(&["--bastion", "bastion", "deploy@web-1", "-p", "2222", "uptime", "-a"]).unwrap();
        assert_eq!(args.destination, "deploy@web-1");
        assert_eq!(args.ssh_args, ["-p", "2222", "uptime", "-a"]);
        let args = parse(&["--bastion", "bastion", "--command", "uptime", "deploy@web-1"]).unwrap();
        assert_eq!(args.command.as_deref(), Some("uptime"));
    }

    #[cfg(feature = "certificates")]
    #[test]
    fn connects_with_a_certificate_unless_through_a_bastion() {
        let args = parse(&["deploy@web-1"]).unwrap();
        assert!(args.bastion.is_none());
        let both = ["--bastion", "bastion", "--server", "web-1", "deploy@web-1"];
        assert!(parse(&both).is_err());
    }

    #[cfg(not(feature = "certificates"))]
    #[test]
    fn requires_a_bastion_without_certificates() {
        assert!(parse(&["deploy@web-1"]).is_err());
        assert!(parse(&["--server", "web-1", "--bastion", "bastion", "deploy@web-1"]).is_err());
    }
}
