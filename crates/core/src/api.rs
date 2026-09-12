//! Messages of the issuer HTTP API, shared by the issuer and the client.
//!
//! - `POST /v1/certificates`: [`CertificateRequest`] → [`CertificateResponse`],
//!   or an [`ErrorResponse`] with status 400 (invalid field), 403 (token
//!   refused, `error` is an [`Error::kind`](crate::Error::kind)), 500 or 503
//!   (busy, retry later). A body that is not a JSON [`CertificateRequest`]
//!   is rejected before that, with a plain-text 413, 415, 400 or 422;
//! - `GET /v1/ca`: the CA public key in OpenSSH format, as plain text;
//! - `GET /v1/root-key`: the Biscuit root public key (`ed25519/...`), as plain
//!   text, so clients can explain refusals with [`failed_checks`](crate::failed_checks).

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Asks for a certificate.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateRequest {
    /// Base64 Biscuit token.
    pub token: String,
    /// OpenSSH public key to certify (`ssh-ed25519 AAAA...`).
    pub public_key: String,
    /// Target server.
    pub server: String,
    /// Account on the target server.
    pub user: String,
    /// Command to force on the session, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

/// A certificate was issued.
#[derive(Debug, Serialize, Deserialize)]
pub struct CertificateResponse {
    /// OpenSSH certificate, to save next to the private key as `<key>-cert.pub`.
    pub certificate: String,
    /// End of validity, in seconds since the Unix epoch (exclusive).
    pub valid_before: u64,
}

/// A request failed.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Short reason, free of token content.
    pub error: String,
    /// On 403, the client address as seen by the issuer: the one tokens are
    /// checked against and certificates are pinned to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<IpAddr>,
    /// On 403, when the token was evaluated, in seconds since the Unix epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<u64>,
}
