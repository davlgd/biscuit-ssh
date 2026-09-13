//! Command-line restriction flags, shared by `token attenuate` and `admin mint`.

use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{Context, bail};
use biscuit_ssh_ca::{fingerprint, parse_public_key};
use biscuit_ssh_core::{Command, Mode, Name, Network, Restriction};

/// Restrictions to add to a token; each flag can be repeated to allow
/// several values.
#[derive(Debug, clap::Args)]
pub struct Restrictions {
    /// Expire after this long, e.g. 90s, 15m, 8h, 30d.
    #[arg(long, value_parser = parse_duration)]
    ttl: Option<Duration>,
    /// Only from this network, e.g. 192.0.2.0/24, 2001:db8::/32 or a single address.
    #[arg(long = "source", value_name = "NETWORK")]
    sources: Vec<Network>,
    /// Only to this server, named as in the token's rights.
    #[arg(long = "server", value_name = "NAME")]
    servers: Vec<Name>,
    /// Only as this account.
    #[arg(long = "user", value_name = "NAME")]
    users: Vec<Name>,
    /// Only with this forced command (interactive sessions are then refused;
    /// the bastion refuses such tokens for now).
    #[arg(long = "command", value_name = "COMMAND")]
    commands: Vec<Command>,
    /// Only with this SSH key: a SHA256 fingerprint or a public key file.
    #[arg(long = "public-key", value_name = "KEY")]
    public_keys: Vec<String>,
    /// Only through this access mode.
    #[arg(long, value_enum)]
    mode: Option<ModeArg>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum ModeArg {
    /// With certificates from the issuer.
    Certificate,
    /// Through the bastion.
    Bastion,
}

impl Restrictions {
    /// Turns the flags into restrictions, in a stable order.
    pub fn build(&self) -> anyhow::Result<Vec<Restriction>> {
        let mut restrictions = Vec::new();
        if let Some(ttl) = self.ttl {
            let expiry = SystemTime::now().checked_add(ttl).context("--ttl is too long")?;
            restrictions.push(Restriction::ExpiresAt(expiry));
        }
        if !self.sources.is_empty() {
            restrictions.push(Restriction::SourceNetworks(self.sources.clone()));
        }
        if !self.servers.is_empty() {
            restrictions.push(Restriction::Servers(self.servers.clone()));
        }
        if !self.users.is_empty() {
            restrictions.push(Restriction::Users(self.users.clone()));
        }
        if !self.commands.is_empty() {
            restrictions.push(Restriction::Commands(self.commands.clone()));
        }
        if !self.public_keys.is_empty() {
            let keys = self
                .public_keys
                .iter()
                .map(|k| resolve_key(k))
                .collect::<Result<_, _>>()?;
            restrictions.push(Restriction::PublicKeys(keys));
        }
        if let Some(mode) = self.mode {
            restrictions.push(Restriction::Mode(match mode {
                ModeArg::Certificate => Mode::Certificate,
                ModeArg::Bastion => Mode::Bastion,
            }));
        }
        Ok(restrictions)
    }
}

/// A fingerprint as is, or the fingerprint of a public key file.
fn resolve_key(key: &str) -> anyhow::Result<String> {
    if key.starts_with("SHA256:") {
        return Ok(key.to_owned());
    }
    let text = std::fs::read_to_string(Path::new(key)).with_context(|| format!("cannot read public key {key}"))?;
    Ok(fingerprint(&parse_public_key(&text)?))
}

/// Parses `<number><unit>` with unit `s`, `m`, `h` or `d`.
fn parse_duration(s: &str) -> anyhow::Result<Duration> {
    let split = s.len().saturating_sub(1);
    let (number, unit) = s.split_at_checked(split).context("expected e.g. 90s, 15m, 8h, 30d")?;
    let unit = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => bail!("unit must be s, m, h or d"),
    };
    let number: u64 = number.parse().context("expected e.g. 90s, 15m, 8h, 30d")?;
    let seconds = number.checked_mul(unit).context("duration is too long")?;
    if seconds == 0 {
        bail!("duration must not be zero");
    }
    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("2d").unwrap(), Duration::from_secs(172_800));
        for bad in [
            "",
            "s",
            "0s",
            "10",
            "10w",
            "-1h",
            "1.5h",
            "99999999999999999999d",
            "213503982334602d",
        ] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }
}
