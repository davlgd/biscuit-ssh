//! `biscuit-ssh`: connects through the bastion, or with certificates from
//! the issuer (`certificates` feature, off by default), restricts and inspects
//! tokens, and administers root keys.

mod askpass;
mod bastion;
#[cfg(feature = "certificates")]
mod certificate;
mod credentials;
mod multiplexing;
mod restrict;
mod ssh;

use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use biscuit_ssh_core::{BlockInfo, KeyPair, PrivateKey, Right, attenuate, inspect, mint};
use clap::{CommandFactory, Parser, Subcommand};

use crate::credentials::TokenSource;
use crate::restrict::Restrictions;

#[derive(Parser)]
#[command(
    version,
    about = "SSH access through Biscuit tokens",
    after_help = "Start with `biscuit-ssh ssh --help`; the README explains the concepts."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[cfg(feature = "certificates")]
    Login(certificate::Args),
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
        #[command(flatten)]
        token: TokenSource,
        #[command(flatten)]
        restrictions: Restrictions,
    },
    /// Show a token's blocks and their revocation identifiers, without
    /// verifying its signature.
    Inspect {
        #[command(flatten)]
        token: TokenSource,
        /// Print a JSON array of `{"index", "revocation_id", "source"}`
        /// objects, one per block, for scripts.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Generate a root key pair: writes the private key, prints the public
    /// key for the services' `root_public_key`.
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
    // `help` only appears once clap builds the command.
    let mut cli = Cli::command();
    cli.build();
    let commands: Vec<String> = cli.get_subcommands().map(|c| c.get_name().to_owned()).collect();
    if let Some(result) = askpass::run_if_requested(&commands) {
        return result;
    }
    match Cli::parse().command {
        #[cfg(feature = "certificates")]
        Command::Login(args) => certificate::run(args),
        Command::Ssh(args) => ssh::run(args),
        Command::Token(TokenCommand::Attenuate { token, restrictions }) => {
            println!("{}", attenuate(&token.read()?, &restrictions.build()?)?);
            Ok(())
        }
        Command::Token(TokenCommand::Inspect { token, json }) => {
            let blocks = inspect(&token.read()?)?;
            if json {
                println!("{}", blocks_json(&blocks));
                return Ok(());
            }
            for (index, block) in blocks.iter().enumerate() {
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
            if !restrictions.expires() {
                eprintln!("warning: without --ttl, this token never expires (only revocation stops it)");
            }
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
            bail!("no token on standard input: use -t FILE, or pipe it with -t -");
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

/// The blocks of a token as a JSON array, for `token inspect --json`.
fn blocks_json(blocks: &[BlockInfo]) -> serde_json::Value {
    blocks
        .iter()
        .enumerate()
        .map(|(index, block)| {
            serde_json::json!({
                "index": index,
                "revocation_id": block.revocation_id,
                "source": block.source.trim(),
            })
        })
        .collect()
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

    /// Checks the whole command line definition, in each feature set: clap
    /// only checks the parts a parse goes through.
    #[test]
    fn defines_a_consistent_command_line() {
        Cli::command().debug_assert();
    }

    #[test]
    fn inspects_tokens_as_json() {
        let root = KeyPair::new();
        let token = mint(&root, &["web-1:deploy".parse().unwrap()], &[]).unwrap();
        let blocks = blocks_json(&inspect(&token).unwrap());
        let block = &blocks.as_array().unwrap()[0];
        assert_eq!(block["index"], 0);
        assert_eq!(block["revocation_id"].as_str().unwrap().len(), 128);
        assert!(
            block["source"]
                .as_str()
                .unwrap()
                .contains("right(\"web-1\", \"deploy\")")
        );
    }

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
