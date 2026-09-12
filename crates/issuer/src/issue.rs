//! Certificate issuance, independent of the HTTP layer.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use biscuit_ssh_ca::{CertificateAuthority, fingerprint, parse_public_key};
use biscuit_ssh_core::api::{CertificateRequest, CertificateResponse};
use biscuit_ssh_core::{AccessRequest, Mode, RevocationList, Verifier};

/// Why a certificate was not issued. Carries no token content.
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    /// The request is malformed.
    #[error("{0}")]
    BadRequest(String),
    /// The token does not allow the request.
    #[error("{kind}")]
    Forbidden {
        /// See [`biscuit_ssh_core::Error::kind`].
        kind: &'static str,
        /// Client address the token was checked against.
        source_ip: IpAddr,
        /// When it was checked, in seconds since the Unix epoch.
        time: u64,
    },
    /// Too many requests are being processed.
    #[error("busy")]
    Busy,
    /// A server-side failure; details are logged, not returned.
    #[error("internal error")]
    Internal,
}

/// Everything needed to turn tokens into certificates.
pub struct Issuer {
    pub(crate) verifier: Verifier,
    pub(crate) ca: CertificateAuthority,
    /// Re-read on every request so revocations apply immediately.
    pub(crate) revocation_list: Option<PathBuf>,
    pub(crate) lifetime: Duration,
    pub(crate) clock_skew: Duration,
}

impl Issuer {
    /// Issues a certificate for `body`, coming from `source_ip`, and writes
    /// the outcome to the audit log.
    ///
    /// Runs Datalog evaluations and signatures: call it off the async runtime.
    pub fn issue(&self, body: &CertificateRequest, source_ip: IpAddr) -> Result<CertificateResponse, IssueError> {
        // Request fields are recorded by try_issue once validated, so
        // malformed input never reaches the logs.
        let span = tracing::info_span!(
            "issue",
            %source_ip,
            server = tracing::field::Empty,
            user = tracing::field::Empty,
            key = tracing::field::Empty,
        );
        let _guard = span.enter();
        let result = self.try_issue(body, source_ip, &span);
        if let Err(e) = &result {
            tracing::warn!(error = %e, "certificate refused");
        }
        result
    }

    fn try_issue(
        &self,
        body: &CertificateRequest,
        source_ip: IpAddr,
        span: &tracing::Span,
    ) -> Result<CertificateResponse, IssueError> {
        let bad_request = |e: &dyn std::fmt::Display| IssueError::BadRequest(e.to_string());
        let key = parse_public_key(&body.public_key).map_err(|e| bad_request(&e))?;
        let request = AccessRequest {
            time: SystemTime::now(),
            source_ip,
            server: body.server.parse().map_err(|e| bad_request(&e))?,
            user: body.user.parse().map_err(|e| bad_request(&e))?,
            command: body
                .command
                .as_deref()
                .map(str::parse)
                .transpose()
                .map_err(|e| bad_request(&e))?,
            public_key: fingerprint(&key),
            mode: Mode::Certificate,
        };
        span.record("server", request.server.as_str())
            .record("user", request.user.as_str())
            .record("key", &request.public_key);

        let revoked = self.revocations()?;
        let authorization = self
            .verifier
            .authorize(&body.token, &request, &revoked, self.lifetime)
            .map_err(|e| match e {
                biscuit_ssh_core::Error::InvalidInput { .. } => bad_request(&e),
                biscuit_ssh_core::Error::Datalog(_) => {
                    tracing::error!(kind = e.kind(), "datalog failure");
                    IssueError::Internal
                }
                _ => IssueError::Forbidden {
                    kind: e.kind(),
                    source_ip,
                    time: request.time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()),
                },
            })?;
        let certificate = self
            .ca
            .sign(&key, &authorization, self.clock_skew)
            .and_then(|c| Ok(c.to_openssh()?))
            .map_err(|e| {
                tracing::error!(error = %e, "signing failure");
                IssueError::Internal
            })?;

        let valid_before = authorization.valid_until();
        tracing::info!(
            command = request.command.as_ref().map(|c| c.as_str()),
            token = authorization.token_id(),
            valid_before,
            "certificate issued",
        );
        Ok(CertificateResponse {
            certificate,
            valid_before,
        })
    }

    fn revocations(&self) -> Result<RevocationList, IssueError> {
        let Some(path) = &self.revocation_list else {
            return Ok(RevocationList::default());
        };
        std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|text| RevocationList::parse(&text).map_err(|e| e.to_string()))
            .map_err(|e| {
                // Fail closed: an unreadable list could hide a revocation.
                tracing::error!(path = %path.display(), error = %e, "cannot read revocation list");
                IssueError::Internal
            })
    }
}

#[cfg(test)]
mod tests {
    use biscuit_ssh_core::{DEFAULT_POLICY, KeyPair, Restriction, mint};
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, Certificate, PrivateKey};

    use super::*;

    struct Setup {
        issuer: Issuer,
        root: KeyPair,
        user_key: String,
    }

    fn setup(revocation_list: Option<PathBuf>) -> Setup {
        let root = KeyPair::new();
        let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let user_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        Setup {
            issuer: Issuer {
                verifier: Verifier::new(root.public(), DEFAULT_POLICY).unwrap(),
                ca: CertificateAuthority::new(ca_key).unwrap(),
                revocation_list,
                lifetime: Duration::from_secs(120),
                clock_skew: Duration::from_secs(30),
            },
            root,
            user_key: user_key.public_key().to_openssh().unwrap(),
        }
    }

    fn body(s: &Setup, restrictions: &[Restriction], server: &str) -> CertificateRequest {
        CertificateRequest {
            token: mint(&s.root, &["web-1:deploy".parse().unwrap()], restrictions).unwrap(),
            public_key: s.user_key.clone(),
            server: server.to_owned(),
            user: "deploy".to_owned(),
            command: None,
        }
    }

    const CLIENT: &str = "192.0.2.7";

    #[test]
    fn issues_certificate_bound_to_client() {
        let s = setup(None);
        let response = s
            .issuer
            .issue(&body(&s, &[], "web-1"), CLIENT.parse().unwrap())
            .unwrap();
        let cert = Certificate::from_openssh(&response.certificate).unwrap();
        assert_eq!(cert.valid_principals(), ["web-1:deploy"]);
        assert_eq!(cert.critical_options().get("source-address").unwrap(), "192.0.2.7/32");
        assert_eq!(cert.valid_before(), response.valid_before);
    }

    #[test]
    fn maps_failures_to_errors() {
        let s = setup(None);
        let ip = CLIENT.parse().unwrap();
        assert!(matches!(
            s.issuer.issue(&body(&s, &[], "web-2"), ip),
            Err(IssueError::Forbidden { kind: "denied", .. })
        ));
        assert!(matches!(
            s.issuer.issue(&body(&s, &[], "web:1"), ip),
            Err(IssueError::BadRequest(_))
        ));
        let mut b = body(&s, &[], "web-1");
        b.token = "garbage".to_owned();
        assert!(matches!(
            s.issuer.issue(&b, ip),
            Err(IssueError::Forbidden {
                kind: "invalid_token",
                ..
            })
        ));
        let nets = vec!["198.51.100.0/24".parse().unwrap()];
        let b = body(&s, &[Restriction::SourceNetworks(nets)], "web-1");
        assert!(matches!(
            s.issuer.issue(&b, ip),
            Err(IssueError::Forbidden { kind: "denied", .. })
        ));
    }

    #[test]
    fn applies_revocations_immediately_and_fails_closed() {
        let path = std::env::temp_dir().join(format!("biscuit-ssh-revoked-{}", std::process::id()));
        let s = setup(Some(path.clone()));
        let b = body(&s, &[], "web-1");
        let ip = CLIENT.parse().unwrap();

        // Missing list: nothing can be issued.
        assert!(matches!(s.issuer.issue(&b, ip), Err(IssueError::Internal)));

        std::fs::write(&path, "").unwrap();
        assert!(s.issuer.issue(&b, ip).is_ok());

        let id = &biscuit_ssh_core::inspect(&b.token).unwrap()[0].revocation_id;
        std::fs::write(&path, id).unwrap();
        assert!(matches!(
            s.issuer.issue(&b, ip),
            Err(IssueError::Forbidden { kind: "revoked", .. })
        ));
        std::fs::remove_file(path).unwrap();
    }
}
