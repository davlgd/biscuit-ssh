//! The token and the SSH key, shared by every way in.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

use crate::read_token;

/// Environment variable holding the token itself, for callers such as
/// agents and CI jobs that receive secrets as variables rather than files.
pub const TOKEN_ENV: &str = "BISCUIT_SSH_TOKEN";

/// Where the token comes from: a file, standard input, or [`TOKEN_ENV`].
#[derive(Debug, clap::Args)]
pub struct TokenSource {
    /// Token file, `-` for standard input [default: the token in BISCUIT_SSH_TOKEN].
    #[arg(short, long, value_name = "FILE", env = "BISCUIT_SSH_TOKEN_FILE")]
    token: Option<PathBuf>,
}

impl TokenSource {
    /// The token, from its file, standard input, or [`TOKEN_ENV`].
    pub fn read(&self) -> anyhow::Result<String> {
        match &self.token {
            Some(path) => read_token(path),
            None => token_from_env(std::env::var(TOKEN_ENV).ok()),
        }
    }
}

/// The token held by [`TOKEN_ENV`], given its value.
fn token_from_env(value: Option<String>) -> anyhow::Result<String> {
    let value = value.context("no token: use -t FILE, BISCUIT_SSH_TOKEN_FILE or BISCUIT_SSH_TOKEN")?;
    let token = value.trim();
    if token.is_empty() {
        bail!("{TOKEN_ENV} is empty");
    }
    Ok(token.to_owned())
}

/// The token, and the SSH key to authenticate with.
#[derive(Debug, clap::Args)]
pub struct Credentials {
    #[command(flatten)]
    token: TokenSource,
    #[cfg_attr(
        feature = "certificates",
        doc = "SSH private key: the one certified by the issuer, which reads its public key from \
               `<identity>.pub`, or presented to the bastion, which requires one \
               [default: ~/.ssh/id_ed25519]."
    )]
    #[cfg_attr(
        not(feature = "certificates"),
        doc = "SSH private key presented to the bastion, which requires one [default: ~/.ssh/id_ed25519]."
    )]
    #[arg(short, long, value_name = "FILE")]
    identity: Option<PathBuf>,
}

impl Credentials {
    /// The SSH private key to use.
    ///
    /// A key given explicitly must exist: `ssh` would otherwise only warn,
    /// and log in with whatever other key it finds. It may be a public key
    /// whose private half an agent holds.
    pub fn identity(&self) -> anyhow::Result<PathBuf> {
        match &self.identity {
            Some(path) => {
                std::fs::metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
                Ok(path.clone())
            }
            None => Ok(
                Path::new(&std::env::var("HOME").context("HOME is not set, use --identity")?).join(".ssh/id_ed25519"),
            ),
        }
    }

    /// The token, from its file, standard input, or [`TOKEN_ENV`].
    pub fn token(&self) -> anyhow::Result<String> {
        self.token.read()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_token_from_its_variable() {
        assert_eq!(token_from_env(Some(" abc\n".to_owned())).unwrap(), "abc");
        assert!(token_from_env(Some(" \n".to_owned())).is_err());
        let missing = token_from_env(None).unwrap_err().to_string();
        assert!(missing.contains("BISCUIT_SSH_TOKEN"), "{missing}");
    }
}
