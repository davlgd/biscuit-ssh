//! Validated inputs of an access request.
//!
//! Server and account names end up in certificate principals (`server:user`)
//! and in file paths on servers, so they are restricted to a conservative
//! character set that keeps both unambiguous.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::SystemTime;

use crate::Error;

/// Longest accepted server or account name.
const MAX_NAME_LEN: usize = 64;

/// Longest accepted forced command.
const MAX_COMMAND_LEN: usize = 1024;

/// A server or account name: 1 to 64 characters among `[A-Za-z0-9._-]`, not
/// starting with `-` (so it can never be read as a command-line option).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name(String);

impl Name {
    /// The name as validated.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Name {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if s.is_empty() || s.len() > MAX_NAME_LEN {
            return Err(Error::invalid("name", "must be 1 to 64 characters long"));
        }
        if s.starts_with('-') {
            return Err(Error::invalid("name", "must not start with '-'"));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(Error::invalid("name", "allowed characters are A-Z a-z 0-9 . _ -"));
        }
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A command to force on the SSH session: printable, single line, at most
/// 1024 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command(String);

impl Command {
    /// The command line as validated.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Command {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        if s.trim().is_empty() || s.len() > MAX_COMMAND_LEN {
            return Err(Error::invalid("command", "must be 1 to 1024 bytes long"));
        }
        if s.chars().any(char::is_control) {
            return Err(Error::invalid("command", "must not contain control characters"));
        }
        Ok(Self(s.to_owned()))
    }
}

/// How the access will be enforced, exposed to tokens as `mode(...)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// A short-lived OpenSSH certificate is issued to the client.
    Certificate,
    /// The client connects through the bastion.
    Bastion,
}

impl Mode {
    /// The value of the `mode` fact.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Certificate => "certificate",
            Self::Bastion => "bastion",
        }
    }
}

/// Everything the verifier knows about an access attempt.
///
/// Each field becomes a Datalog fact (see [`crate::vocabulary`]); the token
/// and the verifier policies decide whether the attempt is allowed.
#[derive(Debug, Clone)]
pub struct AccessRequest {
    /// When the request is evaluated.
    pub time: SystemTime,
    /// Client address as seen by the verifier (never taken from the client's own claims).
    pub source_ip: IpAddr,
    /// Target server.
    pub server: Name,
    /// Account on the target server.
    pub user: Name,
    /// Command the session will be restricted to, if any.
    pub command: Option<Command>,
    /// OpenSSH fingerprint (`SHA256:...`) of the key that will authenticate.
    pub public_key: String,
    /// How access will be enforced.
    pub mode: Mode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_names() {
        for ok in ["web-1", "deploy", "db.eu_west.2", "a"] {
            assert!(ok.parse::<Name>().is_ok(), "{ok}");
        }
        let long = "a".repeat(65);
        for bad in ["", "-rf", "web:1", "a b", "é", "a,b", "a/b", long.as_str()] {
            assert!(bad.parse::<Name>().is_err(), "{bad}");
        }
    }

    #[test]
    fn validates_commands() {
        assert!("uptime".parse::<Command>().is_ok());
        assert!("rsync --server -e.LsfxC . /srv".parse::<Command>().is_ok());
        let long = "a".repeat(1025);
        for bad in ["", "  ", "ls\nrm -rf /", "ls\0", long.as_str()] {
            assert!(bad.parse::<Command>().is_err(), "{bad:?}");
        }
    }
}
