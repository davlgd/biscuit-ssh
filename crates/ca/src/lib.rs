//! OpenSSH user certificate authority of biscuit-ssh.
//!
//! Turns an authorized access request into a short-lived user certificate
//! whose constraints are enforced by `sshd` itself:
//!
//! | Request | Certificate |
//! |---|---|
//! | `server`, `user` | single principal `server:user` (see [`principal`]) |
//! | client address | critical option `source-address` = that address only |
//! | command | critical option `force-command` |
//! | token validity | `valid-before` = [`Authorization::valid_until`] |
//!
//! Only `permit-pty` is granted: no agent, port or X11 forwarding, and no
//! `~/.ssh/rc`. Servers trust the CA with `TrustedUserCAKeys` and map
//! accounts to principals with `AuthorizedPrincipalsFile`.
//!
//! `sshd` checks the certificate only when a session starts: an expiring
//! certificate does not close sessions that are already open. Servers must
//! keep their clock synchronized, since a lagging clock extends validity.

#![warn(missing_docs)]

use std::path::Path;
use std::time::Duration;

use biscuit_ssh_core::{Authorization, Mode, Name, Network};
use ssh_key::certificate::{Builder, CertType};
use ssh_key::rand_core::{OsRng, RngCore};
use ssh_key::{Algorithm, Certificate, HashAlg, PrivateKey, PublicKey};

/// Why a certificate could not be issued.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The CA private key cannot be used.
    #[error("unusable CA key: {0}")]
    Key(String),
    /// The client public key is malformed or of a refused type.
    #[error("unsupported public key: {0}")]
    PublicKey(String),
    /// The authorization does not cover this certificate.
    #[error("refused: {0}")]
    Mismatch(&'static str),
    /// The certificate could not be built or signed.
    #[error("cannot sign certificate: {0}")]
    Signing(#[from] ssh_key::Error),
}

/// The principal a certificate carries for `user` on `server`.
///
/// On each server, `AuthorizedPrincipalsFile` lists for every account the
/// principals allowed to log in as it, typically `<this server>:<account>`.
/// Names cannot contain `:`, so the principal is unambiguous.
pub fn principal(server: &Name, user: &Name) -> String {
    format!("{server}:{user}")
}

/// Parses a client public key in OpenSSH format (`ssh-ed25519 AAAA...`).
///
/// Certificates are refused: a certificate must never be re-certified,
/// and only plain keys can be signed.
pub fn parse_public_key(openssh: &str) -> Result<PublicKey, Error> {
    let key = PublicKey::from_openssh(openssh.trim()).map_err(|e| Error::PublicKey(e.to_string()))?;
    if matches!(key.algorithm(), Algorithm::Dsa | Algorithm::Other(_)) {
        return Err(Error::PublicKey(format!("{} keys are not accepted", key.algorithm())));
    }
    Ok(key)
}

/// The fingerprint tokens refer to in `public_key(...)` facts.
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// Signs user certificates with the CA private key.
pub struct CertificateAuthority {
    key: PrivateKey,
}

impl CertificateAuthority {
    /// Loads an unencrypted OpenSSH private key.
    ///
    /// On Unix, the file must not be readable by group or others, as with
    /// `ssh` itself: a leaked CA key gives access to every server.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let error = |reason: String| Error::Key(format!("{}: {reason}", path.display()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)
                .map_err(|e| error(e.to_string()))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                return Err(error(format!("permissions {:o} are too open, use 600", mode & 0o777)));
            }
        }
        let key = PrivateKey::read_openssh_file(path).map_err(|e| error(e.to_string()))?;
        Self::new(key)
    }

    /// Uses an already loaded private key, which must not be encrypted.
    pub fn new(key: PrivateKey) -> Result<Self, Error> {
        if key.is_encrypted() {
            return Err(Error::Key("encrypted keys are not supported".to_owned()));
        }
        Ok(Self { key })
    }

    /// The CA public key, to install in `TrustedUserCAKeys` on servers.
    pub fn public_key(&self) -> &PublicKey {
        self.key.public_key()
    }

    /// Signs a certificate for `key` granting exactly what `authorization`
    /// allows.
    ///
    /// `key` must be the key the authorization was granted for, and the
    /// authorization must be for certificate mode.
    ///
    /// `skew` backdates the start of validity to tolerate servers whose
    /// clock is slightly behind; the certificate cannot be used before it
    /// exists, so this never opens access earlier than authorized.
    pub fn sign(&self, key: &PublicKey, authorization: &Authorization, skew: Duration) -> Result<Certificate, Error> {
        let request = authorization.request();
        if fingerprint(key) != request.public_key {
            return Err(Error::Mismatch("the key differs from the authorized one"));
        }
        if request.mode != Mode::Certificate {
            return Err(Error::Mismatch("the authorization is not for a certificate"));
        }

        let valid_after = authorization.valid_from().saturating_sub(skew.as_secs());
        let mut builder = Builder::new_with_random_nonce(
            &mut OsRng,
            key.key_data().clone(),
            valid_after,
            authorization.valid_until(),
        )?;
        builder
            .serial(OsRng.next_u64())?
            .cert_type(CertType::User)?
            // sshd logs the key ID at login; the token ID can be added to the
            // revocation list as is.
            .key_id(authorization.token_id())?
            .valid_principal(principal(&request.server, &request.user))?
            .critical_option("source-address", Network::host(request.source_ip).to_string())?
            .extension("permit-pty", "")?;
        if let Some(command) = &request.command {
            builder.critical_option("force-command", command.as_str())?;
        }
        Ok(builder.sign(&self.key)?)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use biscuit_ssh_core::{AccessRequest, DEFAULT_POLICY, KeyPair, RevocationList, Verifier, mint};

    use super::*;

    const ENCRYPTED_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDcX8mjpz
vbLHXF5VmOt5yiAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILFBpn0wxSMAohR1
nm+PR1EGu2mpjijaYFs4uUrU7LvzAAAAkJyPFegX9Q7hyYmeBFx49pzZTCosBLh0hJ3gbq
sPNmfiQx5EI1/1YmkkugdNhmtOLWDGUhRfQAs5ZbzWaCpeR8iv2YcTRSbV+0rtkzZc3fDG
ghr/lfWXu/ve8q2bHvIM1Wwl2+ITmZ4BO7cNQnACP5jkUwTNeFucHx5MkrGOsf2SvRAw6a
k0rB3JgoZjw/ealQ==
-----END OPENSSH PRIVATE KEY-----
";

    fn random_key() -> PrivateKey {
        PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap()
    }

    fn ca() -> CertificateAuthority {
        CertificateAuthority::new(random_key()).unwrap()
    }

    /// Authorizes `key` to log in as deploy on web-1 for 60 seconds.
    fn authorize(key: &PublicKey, command: Option<&str>, mode: Mode) -> Authorization {
        let root = KeyPair::new();
        let token = mint(&root, &["web-1:deploy".parse().unwrap()], &[]).unwrap();
        let request = AccessRequest {
            time: SystemTime::now(),
            source_ip: "::ffff:192.0.2.7".parse().unwrap(),
            server: "web-1".parse().unwrap(),
            user: "deploy".parse().unwrap(),
            command: command.map(|c| c.parse().unwrap()),
            public_key: fingerprint(key),
            mode,
        };
        let verifier = Verifier::new(root.public(), DEFAULT_POLICY).unwrap();
        verifier
            .authorize(&token, &request, &RevocationList::default(), Duration::from_secs(60))
            .unwrap()
    }

    #[test]
    fn certificate_carries_every_constraint() {
        let ca = ca();
        let key = random_key();
        let auth = authorize(key.public_key(), Some("uptime"), Mode::Certificate);
        let cert = ca.sign(key.public_key(), &auth, Duration::from_secs(30)).unwrap();

        cert.validate([&ca.public_key().fingerprint(HashAlg::Sha256)]).unwrap();
        assert_eq!(cert.cert_type(), CertType::User);
        assert_eq!(cert.valid_principals(), ["web-1:deploy"]);
        assert_eq!(cert.key_id(), auth.token_id());
        assert_eq!(cert.critical_options().get("source-address").unwrap(), "192.0.2.7/32");
        assert_eq!(cert.critical_options().get("force-command").unwrap(), "uptime");
        assert_eq!(cert.extensions().keys().collect::<Vec<_>>(), ["permit-pty"]);
        assert_eq!(cert.valid_after(), auth.valid_from() - 30);
        assert_eq!(cert.valid_before(), auth.valid_until());
    }

    #[test]
    fn interactive_certificate_has_no_forced_command() {
        let key = random_key();
        let auth = authorize(key.public_key(), None, Mode::Certificate);
        let cert = ca().sign(key.public_key(), &auth, Duration::ZERO).unwrap();
        assert!(cert.critical_options().get("force-command").is_none());
    }

    #[test]
    fn signs_only_what_was_authorized() {
        let ca = ca();
        let key = random_key();
        let auth = authorize(key.public_key(), None, Mode::Certificate);
        let other = random_key();
        assert!(matches!(
            ca.sign(other.public_key(), &auth, Duration::ZERO),
            Err(Error::Mismatch(_))
        ));

        let bastion = authorize(key.public_key(), None, Mode::Bastion);
        assert!(matches!(
            ca.sign(key.public_key(), &bastion, Duration::ZERO),
            Err(Error::Mismatch(_))
        ));
    }

    #[test]
    fn refuses_certificates_as_public_keys() {
        let key = random_key();
        let auth = authorize(key.public_key(), None, Mode::Certificate);
        let cert = ca().sign(key.public_key(), &auth, Duration::ZERO).unwrap();
        assert!(parse_public_key(&cert.to_openssh().unwrap()).is_err());
        assert!(parse_public_key(&key.public_key().to_openssh().unwrap()).is_ok());
        assert!(parse_public_key("ssh-ed25519 garbage").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn loads_only_private_unencrypted_keys() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("biscuit-ssh-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, content: &str, mode: u32| {
            let path = dir.join(name);
            std::fs::write(&path, content).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path
        };
        let pem = random_key().to_openssh(ssh_key::LineEnding::LF).unwrap();

        assert!(CertificateAuthority::load(&write("ok", &pem, 0o600)).is_ok());
        for (name, content, mode) in [
            ("open", pem.as_str(), 0o644),
            ("malformed", "not a key", 0o600),
            ("encrypted", ENCRYPTED_KEY, 0o600),
        ] {
            let result = CertificateAuthority::load(&write(name, content, mode));
            assert!(matches!(result, Err(Error::Key(_))), "{name}");
        }
        assert!(CertificateAuthority::load(&dir.join("missing")).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
