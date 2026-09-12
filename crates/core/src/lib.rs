//! Authorization core of biscuit-ssh, shared by the certificate issuer, the
//! bastion and the client.
//!
//! A Biscuit token grants `right(server, user)` facts and may carry checks
//! restricting how they are used. The [`Verifier`] describes each access
//! attempt with facts (time, source address, target, command, SSH key) and
//! lets the token's checks and the verifier policies decide. The fact names
//! form a public contract documented in [`vocabulary`].

#![warn(missing_docs)]

#[cfg(feature = "api")]
pub mod api;
mod error;
mod net;
mod request;
mod revocation;
mod token;
mod verifier;
pub mod vocabulary;

pub use biscuit_auth::{KeyPair, PrivateKey, PublicKey};
pub use error::Error;
pub use net::Network;
pub use request::{AccessRequest, Command, Mode, Name};
pub use revocation::RevocationList;
pub use token::{BlockInfo, attenuate, inspect, mint};
pub use verifier::{Authorization, DEFAULT_POLICY, MAX_LIFETIME, MAX_TOKEN_LEN, Verifier, failed_checks};
pub use vocabulary::{Restriction, Right};
