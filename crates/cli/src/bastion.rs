//! Connecting through the bastion: the `ssh` invocation, with `biscuit-ssh`
//! answering the token prompts as askpass (see [`crate::askpass`]).

use std::process::Command;

use anyhow::{Context, bail};
use biscuit_ssh_core::{Restriction, attenuate, bastion_login};

use crate::askpass;
use crate::credentials::Credentials;
use crate::multiplexing;

/// The `ssh` invocation logging in to `bastion` as `user@server`, followed
/// by the user's arguments, unchanged.
///
/// With `command`, the token is first restricted to it: the token alone
/// then never allows the login, so the bastion asks for the command and
/// forces it, even when the original token allows any session. A bastion
/// that doesn't know about commands refuses such a token rather than
/// opening a shell.
///
/// Every invocation logs in afresh, so the bastion checks the token given
/// here, see [`multiplexing`].
///
/// The token and the command reach the askpass process through the
/// environment, which only processes of the same user can read.
pub fn ssh_command(
    credentials: &Credentials,
    bastion: &str,
    (user, server): (&str, &str),
    command: Option<&str>,
    ssh_args: &[String],
) -> anyhow::Result<Command> {
    let (host, port) = split_host_port(bastion)?;
    let identity = credentials.identity()?;
    let myself = std::env::current_exe().context("cannot locate biscuit-ssh")?;
    let mut token = credentials.token()?;
    if let Some(command) = command {
        // The bastion reads it as an answer, which OpenSSH truncates.
        if command.len() > bastion_login::MAX_PART_LEN {
            bail!(
                "--command is too long for the bastion: at most {} bytes",
                bastion_login::MAX_PART_LEN
            );
        }
        multiplexing::refuse(ssh_args)?;
        let command = command.parse().context("invalid --command")?;
        token = attenuate(&token, &[Restriction::Commands(vec![command])])
            .context("cannot restrict the token to --command (a sealed token can't be restricted)")?;
    }

    let mut ssh = Command::new("ssh");
    ssh.env("SSH_ASKPASS", myself)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env(askpass::TOKEN_ENV, token)
        .env(askpass::COMMAND_ENV, command.unwrap_or_default())
        .arg("-i")
        .arg(identity)
        .args(["-o", "IdentitiesOnly=yes"])
        .args(multiplexing::FRESH_LOGIN)
        .args(["-o", "PreferredAuthentications=publickey,keyboard-interactive"]);
    if let Some(port) = port {
        ssh.args(["-p", port]);
    }
    ssh.arg("-l").arg(format!("{user}@{server}")).arg(host).args(ssh_args);
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
    use super::*;

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
