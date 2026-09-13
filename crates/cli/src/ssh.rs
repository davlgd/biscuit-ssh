//! `biscuit-ssh ssh`: connects with a certificate from the issuer, or
//! through the bastion.

use std::process::Command;

use anyhow::Context;

use crate::askpass;
use crate::login::{Login, Options, login};

/// Gets a certificate and connects with it, e.g.
/// `biscuit-ssh ssh deploy@web-1.example.com -p 2222 uptime`, or connects
/// through a bastion with `--bastion`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// Where to connect, as `user@host`.
    destination: String,
    /// Server name in the token, when it differs from the host of
    /// DESTINATION, e.g. when connecting by address [default: that host].
    #[arg(long)]
    server: Option<String>,
    /// Connect through this bastion, `host` or `host:port`, instead of
    /// getting a certificate: DESTINATION is then `user@server`, with the
    /// server named as in the token.
    #[arg(long, value_name = "HOST[:PORT]", conflicts_with_all = ["server", "command"])]
    bastion: Option<String>,
    #[command(flatten)]
    options: Options,
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
        Some(bastion) => bastion_command(&args.options, bastion, &args.destination, &args.ssh_args)?,
        None => {
            let server = args.server.as_deref().unwrap_or(host);
            let login = login(&args.options, server, user)?;
            ssh_command(&login, &args.destination, &args.ssh_args)?
        }
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

/// The `ssh` invocation using exactly the new certificate, followed by the
/// destination and the user's arguments, unchanged.
///
/// The certificate only accepts the address the issuer saw, so `ssh` is
/// kept on the matching address family: a dual-stack client reaching the
/// issuer over IPv4 and the server over IPv6 would otherwise be refused. It
/// cannot guarantee the same address (several interfaces, different NAT).
fn ssh_command(login: &Login, destination: &str, ssh_args: &[String]) -> anyhow::Result<Command> {
    let source = login
        .certificate
        .critical_options()
        .get("source-address")
        .context("the certificate has no source-address")?;
    let family = if source.contains(':') { "-6" } else { "-4" };
    // `-o` values follow ssh_config syntax: quote the path so spaces survive,
    // and refuse the characters that quoting would not protect.
    let certificate = login
        .certificate_path
        .to_str()
        .filter(|path| !path.contains(['"', '\\']))
        .context("the certificate path must be UTF-8 without quotes or backslashes")?;

    let mut ssh = Command::new("ssh");
    ssh.arg(family)
        .arg("-i")
        .arg(&login.identity)
        .arg("-o")
        .arg(format!("CertificateFile=\"{certificate}\""))
        .args(["-o", "IdentitiesOnly=yes"])
        .arg(destination)
        .args(ssh_args);
    Ok(ssh)
}

/// The `ssh` invocation logging in to the bastion as `user@server`, with
/// `biscuit-ssh` answering its token prompt (see [`crate::askpass`]).
///
/// The token reaches the askpass process through the environment, which
/// only processes of the same user can read.
fn bastion_command(options: &Options, bastion: &str, login: &str, ssh_args: &[String]) -> anyhow::Result<Command> {
    let (host, port) = split_host_port(bastion)?;
    let identity = options.identity()?;
    let myself = std::env::current_exe().context("cannot locate biscuit-ssh")?;

    let mut ssh = Command::new("ssh");
    ssh.env("SSH_ASKPASS", myself)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env(askpass::TOKEN_ENV, options.token()?)
        .arg("-i")
        .arg(identity)
        .args(["-o", "IdentitiesOnly=yes"])
        .args(["-o", "PreferredAuthentications=publickey,keyboard-interactive"]);
    if let Some(port) = port {
        ssh.args(["-p", port]);
    }
    ssh.args(["-l", login]).arg(host).args(ssh_args);
    Ok(ssh)
}

/// Splits `host`, `host:port` or `[ipv6]:port`.
fn split_host_port(address: &str) -> anyhow::Result<(&str, Option<&str>)> {
    let (host, port) = match address.strip_prefix('[') {
        Some(rest) => {
            let (host, rest) = rest.split_once(']').context("unclosed [ in the bastion address")?;
            let port = match rest {
                "" => None,
                _ => Some(rest.strip_prefix(':').context("unexpected text after ]")?),
            };
            (host, port)
        }
        None => match address.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (address, None),
        },
    };
    if host.is_empty() || host.starts_with('-') || port.is_some_and(|p| p.parse::<u16>().is_err()) {
        anyhow::bail!("the bastion must be host, host:port or [ipv6]:port");
    }
    Ok((host, port))
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

    fn parse(line: &[&str]) -> Args {
        let argv = ["biscuit-ssh", "--issuer", "https://ca.example.com", "-t", "token"];
        Cli::parse_from(argv.iter().chain(line)).args
    }

    fn login(identity: &str, source: &str) -> Login {
        Login {
            identity: identity.into(),
            certificate_path: format!("{identity}-cert.pub").into(),
            certificate: test_certificate(source),
        }
    }

    #[test]
    fn passes_ssh_arguments_through_after_the_destination() {
        let args = parse(&["deploy@web-1", "-p", "2222", "uptime", "-a"]);
        assert_eq!(args.destination, "deploy@web-1");
        assert_eq!(args.ssh_args, ["-p", "2222", "uptime", "-a"]);

        let ssh = ssh_command(&login("id", "192.0.2.7/32"), &args.destination, &args.ssh_args).unwrap();
        let argv: Vec<_> = ssh.get_args().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            argv,
            [
                "-4",
                "-i",
                "id",
                "-o",
                "CertificateFile=\"id-cert.pub\"",
                "-o",
                "IdentitiesOnly=yes",
                "deploy@web-1",
                "-p",
                "2222",
                "uptime",
                "-a"
            ]
        );
    }

    #[test]
    fn refuses_certificate_paths_ssh_config_cannot_quote() {
        for identity in ["a\"b/id", "a\\b/id"] {
            assert!(ssh_command(&login(identity, "192.0.2.7/32"), "deploy@web-1", &[]).is_err());
        }
    }

    /// Checks how OpenSSH itself reads the arguments (`ssh -G` only prints
    /// the resulting configuration). Skipped when `ssh` is not installed.
    #[test]
    fn openssh_reads_arguments_as_intended() {
        // A path with a space, to an existing file: ssh ignores missing ones.
        let dir = std::env::temp_dir().join(format!("biscuit ssh {}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let identity = dir.join("id");
        std::fs::write(&identity, "").unwrap();
        let identity = identity.to_str().unwrap();

        let args = parse(&["deploy@web-1", "-p", "2222", "uptime"]);
        let ssh = ssh_command(&login(identity, "192.0.2.7/32"), &args.destination, &args.ssh_args).unwrap();
        let output = Command::new("ssh")
            .args(["-G", "-F", "/dev/null"])
            .args(ssh.get_args())
            .output();
        std::fs::remove_dir_all(&dir).unwrap();
        let Ok(output) = output else {
            return;
        };
        let config = String::from_utf8_lossy(&output.stdout);
        for expected in [
            "user deploy".to_owned(),
            "hostname web-1".to_owned(),
            "port 2222".to_owned(),
            "addressfamily inet".to_owned(),
            "identitiesonly yes".to_owned(),
            format!("identityfile {identity}"),
            format!("certificatefile {identity}-cert.pub"),
        ] {
            assert!(
                config.lines().any(|l| l == expected),
                "{expected} missing in:\n{config}"
            );
        }
    }

    #[test]
    fn keeps_the_address_family_seen_by_the_issuer() {
        let ssh = ssh_command(&login("id", "2001:db8::1/128"), "deploy@web-1", &[]).unwrap();
        assert_eq!(ssh.get_args().next().unwrap(), "-6");
    }

    fn test_certificate(source: &str) -> ssh_key::Certificate {
        use ssh_key::rand_core::OsRng;
        use ssh_key::{Algorithm, PrivateKey, certificate};

        let ca = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut builder =
            certificate::Builder::new_with_random_nonce(&mut OsRng, key.public_key().key_data().clone(), 0, 1).unwrap();
        builder
            .valid_principal("web-1:deploy")
            .unwrap()
            .critical_option("source-address", source)
            .unwrap();
        builder.sign(&ca).unwrap()
    }

    #[test]
    fn splits_bastion_addresses() {
        assert_eq!(split_host_port("bastion").unwrap(), ("bastion", None));
        assert_eq!(split_host_port("bastion:2200").unwrap(), ("bastion", Some("2200")));
        assert_eq!(
            split_host_port("[2001:db8::1]:2200").unwrap(),
            ("2001:db8::1", Some("2200"))
        );
        for bad in [
            "",
            ":22",
            "bastion:ssh",
            "bastion:70000",
            "-oProxyCommand=x",
            "[::1",
            "[::1]garbage",
            "[bastion]ignored",
            "[::1]:",
        ] {
            assert!(split_host_port(bad).is_err(), "{bad}");
        }
    }
}
