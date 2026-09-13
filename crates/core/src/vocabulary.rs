//! The Datalog vocabulary: the public contract between the token issuer, token
//! holders and verifiers. Renaming a fact or changing its arity breaks every
//! token in circulation.
//!
//! The authority block grants access with facts:
//!
//! | Fact | Meaning |
//! |---|---|
//! | `right($server, $user)` | may log in as `$user` on `$server` |
//!
//! The verifier describes each request with facts:
//!
//! | Fact | Meaning |
//! |---|---|
//! | `time($t)` | evaluation time |
//! | `source_ip($ip)` | client address, e.g. `"192.0.2.7"` |
//! | `source_net($cidr)` | one fact per network enclosing the client address, from `"0.0.0.0/0"` to `"192.0.2.7/32"` (see [`Network`]) |
//! | `server($name)` | target server |
//! | `user($name)` | account on the target server |
//! | `command($cmd)` | forced command, only present when one is requested |
//! | `public_key($fingerprint)` | `SHA256:...` fingerprint of the SSH key that will log in |
//! | `mode($mode)` | `"certificate"` or `"bastion"` |
//!
//! Any block can then restrict the token with checks on those facts; the
//! [`Restriction`] type builds the common ones.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use biscuit_auth::builder::{Check, Fact, Term, fact, string};

use crate::{AccessRequest, Command, Error, Mode, Name, Network};

/// Permission to log in as `user` on `server`, written `server:user`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Right {
    /// Server the right applies to.
    pub server: Name,
    /// Account on that server.
    pub user: Name,
}

impl Right {
    /// The authority fact granting this right.
    pub fn to_fact(&self) -> Fact {
        fact("right", &[string(self.server.as_str()), string(self.user.as_str())])
    }
}

impl FromStr for Right {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        let (server, user) = s
            .split_once(':')
            .ok_or(Error::invalid("right", "expected server:user"))?;
        Ok(Self {
            server: server.parse()?,
            user: user.parse()?,
        })
    }
}

impl fmt::Display for Right {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.server, self.user)
    }
}

/// A typed restriction, turned into a Datalog check.
///
/// Every restriction requires the matching request fact to exist, so a
/// token restricted to commands cannot be used for an interactive session.
#[derive(Debug, Clone)]
pub enum Restriction {
    /// Valid until this time (inclusive).
    ExpiresAt(SystemTime),
    /// Client address must belong to one of these networks.
    SourceNetworks(Vec<Network>),
    /// Only these servers may be reached.
    Servers(Vec<Name>),
    /// Only these accounts may be used.
    Users(Vec<Name>),
    /// The session must be forced to one of these commands.
    Commands(Vec<Command>),
    /// Only these SSH keys (`SHA256:...` fingerprints) may log in.
    PublicKeys(Vec<String>),
    /// Access must be enforced this way.
    Mode(Mode),
}

impl Restriction {
    /// The Datalog check enforcing this restriction.
    ///
    /// Values are bound as parameters, never interpolated into source code.
    pub fn to_check(&self) -> Result<Check, Error> {
        let (source, value) = match self {
            Self::ExpiresAt(t) => ("check if time($t), $t <= {v}", Term::Date(unix_seconds(*t)?)),
            Self::SourceNetworks(v) => ("check if source_net($n), {v}.contains($n)", set(v)?),
            Self::Servers(v) => ("check if server($s), {v}.contains($s)", set(v)?),
            Self::Users(v) => ("check if user($u), {v}.contains($u)", set(v)?),
            Self::Commands(v) => (
                "check if command($c), {v}.contains($c)",
                set(v.iter().map(Command::as_str))?,
            ),
            Self::PublicKeys(v) => ("check if public_key($k), {v}.contains($k)", set(v)?),
            Self::Mode(m) => ("check if mode({v})", string(m.as_str())),
        };
        let mut check = Check::try_from(source).map_err(Error::Datalog)?;
        check.set("v", value).map_err(Error::Datalog)?;
        Ok(check)
    }
}

/// A Datalog set of strings; empty sets are refused since they would make a
/// check that can never pass, which is almost certainly a mistake.
fn set<T: ToString>(values: impl IntoIterator<Item = T>) -> Result<Term, Error> {
    let set: BTreeSet<Term> = values.into_iter().map(|v| string(&v.to_string())).collect();
    if set.is_empty() {
        return Err(Error::invalid("restriction", "needs at least one value"));
    }
    Ok(Term::Set(set))
}

/// Seconds since the Unix epoch, the resolution of Biscuit dates.
///
/// Earlier times are refused rather than clamped (Biscuit's own conversion
/// panics on them).
pub(crate) fn unix_seconds(time: SystemTime) -> Result<u64, Error> {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::invalid("time", "before the Unix epoch"))
}

/// The `time` fact for `seconds` since the Unix epoch.
pub(crate) fn time_fact(seconds: u64) -> Fact {
    fact("time", &[Term::Date(seconds)])
}

/// The facts describing `request`, as listed in the module documentation,
/// except `time`: the verifier evaluates the same request at several times.
pub(crate) fn request_facts(request: &AccessRequest) -> Vec<Fact> {
    let mut facts = vec![
        fact("source_ip", &[string(&request.source_ip.to_canonical().to_string())]),
        fact("server", &[string(request.server.as_str())]),
        fact("user", &[string(request.user.as_str())]),
        fact("public_key", &[string(&request.public_key)]),
        fact("mode", &[string(request.mode.as_str())]),
    ];
    facts.extend(Network::enclosing(request.source_ip).map(|n| fact("source_net", &[string(&n.to_string())])));
    if let Some(command) = &request.command {
        facts.push(fact("command", &[string(command.as_str())]));
    }
    facts
}
