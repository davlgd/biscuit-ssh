//! Answering `ssh` prompts while connecting through the bastion.
//!
//! `biscuit-ssh ssh --bastion` runs `ssh` with itself as `SSH_ASKPASS`, and
//! the token in [`TOKEN_ENV`]. `ssh` then runs `biscuit-ssh <prompt>` for
//! each question: the bastion's token prompts are answered with the token
//! (see [`bastion_login`]); any other one (key passphrase, host key
//! confirmation) is asked on the terminal, so the token can never answer
//! something else.

use std::io::{BufRead, Write};

use anyhow::Context;
use biscuit_ssh_core::bastion_login;

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

/// Help for scripts, which have no terminal to answer host key questions.
const NO_TERMINAL: &str = "no terminal to answer ssh's question (for scripts, trust the bastion's host key \
    beforehand: -o UserKnownHostsFile=FILE with its key, or -o StrictHostKeyChecking=accept-new)";

fn answer(prompt: &str, token: &str) -> anyhow::Result<()> {
    if let Some(part) = bastion_login::parse_prompt(prompt) {
        let answer =
            bastion_login::answer(token, part).context("the bastion asked for more of the token than exists")?;
        println!("{answer}");
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
        _ => rpassword::prompt_password(prompt).context(NO_TERMINAL)?,
    };
    println!("{answer}");
    Ok(())
}

/// Reads an answer on the terminal, with echo.
fn read_visible(prompt: &str) -> anyhow::Result<String> {
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context(NO_TERMINAL)?;
    write!(tty, "{prompt}")?;
    let mut line = String::new();
    std::io::BufReader::new(tty).read_line(&mut line)?;
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}
