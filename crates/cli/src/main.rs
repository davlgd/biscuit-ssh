//! `biscuit-ssh`: gets SSH certificates from the issuer, restricts and
//! inspects tokens, and administers root keys.

mod askpass;
mod login;
mod restrict;
mod ssh;

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use biscuit_ssh_core::{KeyPair, PrivateKey, Right, attenuate, inspect, mint};
use clap::{Parser, Subcommand};

use crate::restrict::Restrictions;

#[derive(Parser)]
#[command(version, about = "SSH access through Biscuit tokens")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Login(login::Args),
    Ssh(ssh::Args),
    /// Restrict or inspect tokens.
    #[command(subcommand)]
    Token(TokenCommand),
    /// Manage root keys and create tokens.
    #[command(subcommand)]
    Admin(AdminCommand),
}

#[derive(Subcommand)]
enum TokenCommand {
    /// Add restrictions to a token, e.g. before handing it over; prints the
    /// new token.
    Attenuate {
        /// Token file, `-` for standard input.
        #[arg(short, long, value_name = "FILE", env = "BISCUIT_SSH_TOKEN_FILE")]
        token: PathBuf,
        #[command(flatten)]
        restrictions: Restrictions,
    },
    /// Show a token's blocks and their revocation identifiers, without
    /// verifying its signature.
    Inspect {
        /// Token file, `-` for standard input.
        #[arg(short, long, value_name = "FILE", env = "BISCUIT_SSH_TOKEN_FILE")]
        token: PathBuf,
    },
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Generate a root key pair: writes the private key, prints the public
    /// key for the issuer's `root_public_key`.
    Keygen {
        /// New file for the private key (created with mode 600).
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Create a token signed by the root key; prints it.
    Mint {
        /// Root private key file.
        #[arg(short, long)]
        key: PathBuf,
        /// Allow logging in as `user` on `server`; repeat for several.
        #[arg(short, long = "right", value_name = "SERVER:USER", required = true)]
        rights: Vec<Right>,
        #[command(flatten)]
        restrictions: Restrictions,
    },
}

fn main() -> anyhow::Result<()> {
    if let Some(result) = askpass::run_if_requested() {
        return result;
    }
    match Cli::parse().command {
        Command::Login(args) => login::run(args),
        Command::Ssh(args) => ssh::run(args),
        Command::Token(TokenCommand::Attenuate { token, restrictions }) => {
            println!("{}", attenuate(&read_token(&token)?, &restrictions.build()?)?);
            Ok(())
        }
        Command::Token(TokenCommand::Inspect { token }) => {
            for (index, block) in inspect(&read_token(&token)?)?.iter().enumerate() {
                println!("# block {index}, revocation id {}", block.revocation_id);
                println!("{}\n", block.source.trim());
            }
            Ok(())
        }
        Command::Admin(AdminCommand::Keygen { output }) => {
            let root = KeyPair::new();
            write_secret(&output, &root.private().to_prefixed_string())?;
            println!("{}", root.public());
            Ok(())
        }
        Command::Admin(AdminCommand::Mint {
            key,
            rights,
            restrictions,
        }) => {
            let text = std::fs::read_to_string(&key).with_context(|| format!("cannot read {}", key.display()))?;
            let private: PrivateKey = text.trim().parse().context("invalid root private key")?;
            println!("{}", mint(&KeyPair::from(&private), &rights, &restrictions.build()?)?);
            Ok(())
        }
    }
}

/// Reads a token from `path`, or standard input for `-`.
pub(crate) fn read_token(path: &Path) -> anyhow::Result<String> {
    let mut token = String::new();
    if path == Path::new("-") {
        if std::io::stdin().is_terminal() {
            bail!("no token given: use --token FILE, set BISCUIT_SSH_TOKEN_FILE, or pipe it");
        }
        std::io::stdin()
            .read_to_string(&mut token)
            .context("cannot read token from standard input")?;
    } else {
        token = std::fs::read_to_string(path).with_context(|| format!("cannot read token {}", path.display()))?;
    }
    let token = token.trim();
    if token.is_empty() {
        bail!("the token is empty");
    }
    Ok(token.to_owned())
}

/// Writes a new file readable by its owner only; never overwrites.
fn write_secret(path: &Path, content: &str) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    writeln!(file, "{content}").with_context(|| format!("cannot write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_empty_tokens() {
        let path = std::env::temp_dir().join(format!("biscuit-ssh-token-{}", std::process::id()));
        std::fs::write(&path, " \n\t").unwrap();
        let error = read_token(&path).unwrap_err().to_string();
        std::fs::write(&path, " abc\n").unwrap();
        let token = read_token(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(error, "the token is empty");
        assert_eq!(token, "abc");
    }
}
