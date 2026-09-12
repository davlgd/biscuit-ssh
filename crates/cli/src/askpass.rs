//! Answering `ssh` prompts while connecting through the bastion.
//!
//! `biscuit-ssh ssh --bastion` runs `ssh` with itself as `SSH_ASKPASS`, and
//! the token in [`TOKEN_ENV`]. `ssh` then runs `biscuit-ssh <prompt>` for
//! each question: the bastion's token prompt is answered with the token;
//! any other one (key passphrase, host key confirmation) is asked on the
//! terminal, so the token can never answer something else.

use std::io::{BufRead, Write};

use anyhow::Context;
use biscuit_ssh_core::api::BASTION_TOKEN_PROMPT;

/// Environment variable carrying the token to `biscuit-ssh` run as askpass.
pub const TOKEN_ENV: &str = "BISCUIT_SSH_ASKPASS_TOKEN";

/// Runs as askpass when `ssh` started this process for a prompt: returns
/// `None` otherwise.
pub fn run_if_requested() -> Option<anyhow::Result<()>> {
    let token = std::env::var(TOKEN_ENV).ok()?;
    let mut args = std::env::args().skip(1);
    let (Some(prompt), None) = (args.next(), args.next()) else {
        return None;
    };
    Some(answer(&prompt, &token))
}

fn answer(prompt: &str, token: &str) -> anyhow::Result<()> {
    if is_token_prompt(prompt) {
        println!("{token}");
        return Ok(());
    }
    let answer = match std::env::var("SSH_ASKPASS_PROMPT").as_deref() {
        // A notice, e.g. "touch your security key": show it, nothing to read.
        Ok("none") => {
            eprintln!("{prompt}");
            return Ok(());
        }
        // Questions like the host key confirmation are answered visibly.
        _ if prompt.contains("yes/no") => read_visible(prompt)?,
        _ => rpassword::prompt_password(prompt).context("cannot read from the terminal")?,
    };
    println!("{answer}");
    Ok(())
}

/// Whether `ssh` is showing the bastion's token prompt: as is, or prefixed
/// with `(login@host) ` as recent OpenSSH versions do.
fn is_token_prompt(prompt: &str) -> bool {
    let Some(prefix) = prompt.strip_suffix(BASTION_TOKEN_PROMPT) else {
        return false;
    };
    prefix.is_empty()
        || prefix
            .strip_prefix('(')
            .and_then(|login| login.strip_suffix(") "))
            .is_some_and(|login| !login.contains(['(', ')']))
}

/// Reads an answer on the terminal, with echo.
fn read_visible(prompt: &str) -> anyhow::Result<String> {
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("cannot open the terminal")?;
    write!(tty, "{prompt}")?;
    let mut line = String::new();
    std::io::BufReader::new(tty).read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_the_token_prompt() {
        for ok in ["Biscuit token: ", "(deploy@web-1@bastion.example.com) Biscuit token: "] {
            assert!(is_token_prompt(ok), "{ok}");
        }
        for bad in [
            "Enter passphrase for key 'id': ",
            "Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
            "Password: ",
            "Biscuit token:",
            "x Biscuit token: ",
            "(a) (b) Biscuit token: ",
            "Biscuit token: Biscuit token: ",
        ] {
            assert!(!is_token_prompt(bad), "{bad}");
        }
    }
}
