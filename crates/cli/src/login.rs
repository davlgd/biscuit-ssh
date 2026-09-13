//! `biscuit-ssh login`: exchanges a token for a certificate.

use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use biscuit_ssh_ca::{fingerprint, parse_public_key};
use biscuit_ssh_core::api::{CertificateRequest, CertificateResponse, ErrorResponse};
use biscuit_ssh_core::{AccessRequest, Mode, PublicKey, Right, failed_checks, granted_rights};
use ssh_key::Certificate;
use ureq::http::Uri;
use ureq::tls::{PemItem, RootCerts, TlsConfig};

use crate::read_token;

/// Bounds each exchange with the issuer.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Get a certificate for plain `ssh` and other tools.
///
/// The certificate is written next to the private key, as
/// `<identity>-cert.pub`, where `ssh` finds it by itself; it is valid for a
/// few minutes. Example: `biscuit-ssh login web-1 deploy -t my.token`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// Target server, as named in the token.
    server: String,
    /// Account on the target server.
    user: String,
    #[command(flatten)]
    options: Options,
}

/// The token, the key, and how to reach the issuer; shared with `ssh`.
#[derive(Debug, clap::Args)]
pub struct Options {
    /// Token file, `-` for standard input.
    #[arg(short, long, value_name = "FILE", env = "BISCUIT_SSH_TOKEN_FILE")]
    token: PathBuf,
    /// SSH private key: the one certified by the issuer, or presented to the
    /// bastion (which requires one); its public key is read from
    /// `<identity>.pub` [default: ~/.ssh/id_ed25519].
    #[arg(short, long, value_name = "FILE")]
    identity: Option<PathBuf>,
    /// Issuer URL, e.g. `https://ssh-ca.example.com` (certificates only).
    #[arg(long, env = "BISCUIT_SSH_ISSUER")]
    issuer: Option<String>,
    /// PEM root certificate to trust for the issuer instead of the public
    /// web PKI, for a private deployment (certificates only).
    #[arg(long, value_name = "FILE", env = "BISCUIT_SSH_ISSUER_CA")]
    issuer_ca: Option<PathBuf>,
    /// Command to force on the session, when the token requires one
    /// (certificates only).
    #[arg(long)]
    command: Option<String>,
}

impl Options {
    /// The issuer URL, required to get certificates.
    fn issuer(&self) -> anyhow::Result<&str> {
        self.issuer
            .as_deref()
            .context("no issuer: use --issuer or set BISCUIT_SSH_ISSUER")
    }

    /// The SSH private key to use.
    pub fn identity(&self) -> anyhow::Result<PathBuf> {
        match &self.identity {
            Some(path) => Ok(path.clone()),
            None => Ok(
                Path::new(&std::env::var("HOME").context("HOME is not set, use --identity")?).join(".ssh/id_ed25519"),
            ),
        }
    }

    /// The token, from its file or standard input.
    pub fn token(&self) -> anyhow::Result<String> {
        read_token(&self.token)
    }
}

/// A certificate obtained and installed.
pub struct Login {
    /// Private key the certificate goes with.
    pub identity: PathBuf,
    /// Where the certificate was written.
    pub certificate_path: PathBuf,
    /// The certificate itself.
    pub certificate: Certificate,
}

/// Runs `biscuit-ssh login`.
pub fn run(args: Args) -> anyhow::Result<()> {
    login(&args.options, &args.server, &args.user).map(drop)
}

/// Requests a certificate for `user` on `server` and writes it next to the
/// identity.
pub fn login(options: &Options, server: &str, user: &str) -> anyhow::Result<Login> {
    let url = endpoint(options.issuer()?, "certificates")?;
    let identity = options.identity()?;
    let public_key_path = with_suffix(&identity, ".pub");
    let public_key = std::fs::read_to_string(&public_key_path)
        .with_context(|| format!("cannot read {}", public_key_path.display()))?;
    let key = parse_public_key(&public_key)?;

    let request = CertificateRequest {
        token: options.token()?,
        public_key: public_key.trim().to_owned(),
        server: server.to_owned(),
        user: user.to_owned(),
        command: options.command.clone(),
    };
    let agent = agent(options.issuer_ca.as_deref())?;
    let mut response = agent.post(&url).send_json(&request).map_err(|e| {
        let hint = match e.to_string().contains("UnknownIssuer") {
            true => " (if the issuer uses a private CA, pass it with --issuer-ca)",
            false => "",
        };
        anyhow::Error::new(e).context(format!("cannot reach {url}{hint}"))
    })?;
    if !response.status().is_success() {
        let status = response.status();
        let refusal = response.body_mut().read_json::<ErrorResponse>().ok();
        let reason = refusal.as_ref().map_or("no details", |r| r.error.as_str());
        let mut message = format!("the issuer refused ({status}): {reason}");
        if let Some(source_ip) = refusal.as_ref().and_then(|r| r.source_ip) {
            message.push_str(&format!("\n  your address, as seen by the issuer: {source_ip}"));
            let time = refusal.as_ref().and_then(|r| r.time);
            if let (Some(time), "denied") = (time, reason) {
                message.push_str(&explain(&agent, options, &request, &key, source_ip, time));
            }
        }
        bail!(message);
    }
    let issued: CertificateResponse = response.body_mut().read_json().context("invalid issuer response")?;
    let certificate = Certificate::from_openssh(&issued.certificate).context("invalid certificate from issuer")?;
    if certificate.public_key() != key.key_data() {
        bail!("the issuer certified another key");
    }

    let certificate_path = with_suffix(&identity, "-cert.pub");
    let replaced = certificate_path.exists();
    replace_file(&certificate_path, &format!("{}\n", issued.certificate))
        .with_context(|| format!("cannot write {}", certificate_path.display()))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    eprintln!(
        "Certificate for {user}@{server} {} {}, valid for {} s",
        if replaced { "replaced in" } else { "written to" },
        certificate_path.display(),
        issued.valid_before.saturating_sub(now),
    );
    Ok(Login {
        identity,
        certificate_path,
        certificate,
    })
}

/// Hints at why a token was denied, by evaluating its own checks locally
/// with the address and time the issuer used.
///
/// Only a hint: the issuer's policies and any facts they add are unknown
/// here. Any failure leaves the original refusal as the only answer.
fn explain(
    agent: &ureq::Agent,
    options: &Options,
    request: &CertificateRequest,
    key: &ssh_key::PublicKey,
    source_ip: IpAddr,
    time: u64,
) -> String {
    let failed = (|| -> anyhow::Result<(Vec<String>, Vec<Right>)> {
        let url = endpoint(options.issuer()?, "root-key")?;
        let root_key: PublicKey = agent
            .get(&url)
            .call()?
            .body_mut()
            .read_to_string()?
            .trim()
            .parse()
            .context("invalid root key")?;
        let access = AccessRequest {
            time: UNIX_EPOCH
                .checked_add(Duration::from_secs(time))
                .context("invalid time from issuer")?,
            source_ip,
            server: request.server.parse()?,
            user: request.user.parse()?,
            command: request.command.as_deref().map(str::parse).transpose()?,
            public_key: fingerprint(key),
            mode: Mode::Certificate,
        };
        let failed = failed_checks(root_key, &request.token, &access)?;
        Ok((failed, granted_rights(root_key, &request.token)?))
    })();
    match failed {
        Ok((checks, rights)) if checks.is_empty() => {
            let granted: Vec<String> = rights.iter().map(ToString::to_string).collect();
            let requested = format!("{}:{}", request.server, request.user);
            if granted.contains(&requested) {
                "\n  hint: no restriction of the token fails locally; the issuer's policy may refuse it".to_owned()
            } else {
                format!(
                    "\n  hint: the token grants {} but not {requested}; name the server as in the token \
                     (with `biscuit-ssh ssh`, use --server when connecting by address)",
                    granted.join(", ")
                )
            }
        }
        Ok((checks, _)) => {
            let list: String = checks.iter().map(|c| format!("\n    {c}")).collect();
            format!("\n  hint: restrictions of the token failing when evaluated locally:{list}")
        }
        Err(e) => format!("\n  (cannot explain the refusal: {e})"),
    }
}

/// The URL of `path` under `/v1/` of the `issuer` base URL.
///
/// Tokens are bearer credentials: they only travel over HTTPS, or plain HTTP
/// to this machine. Credentials, queries and fragments are refused: they are
/// never needed, and hide where the request actually goes.
fn endpoint(issuer: &str, path: &str) -> anyhow::Result<String> {
    let uri: Uri = issuer.parse().context("invalid issuer URL")?;
    let authority = uri.authority().context("the issuer URL needs a host")?;
    if authority.as_str().contains('@') {
        bail!("the issuer URL must not contain credentials");
    }
    // `Uri` silently drops fragments, so look for them in the raw string.
    if uri.query().is_some() || issuer.contains('#') {
        bail!("the issuer URL must not contain a query or a fragment");
    }
    let scheme = uri.scheme_str().unwrap_or_default();
    match scheme {
        "https" => {}
        "http" if matches!(authority.host(), "localhost" | "127.0.0.1" | "[::1]") => {}
        "http" => bail!("plain http:// is only allowed to localhost, use https://"),
        _ => bail!("the issuer URL must start with https://"),
    }
    Ok(format!(
        "{scheme}://{authority}{}/v1/{path}",
        uri.path().trim_end_matches('/')
    ))
}

/// An HTTP agent that reports error statuses as responses, so their body can
/// be shown, never follows redirects, and trusts `issuer_ca` instead of the
/// web PKI when given.
fn agent(issuer_ca: Option<&Path>) -> anyhow::Result<ureq::Agent> {
    let mut config = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(TIMEOUT));
    if let Some(path) = issuer_ca {
        let pem = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        let mut certs = Vec::new();
        for item in ureq::tls::parse_pem(&pem) {
            if let PemItem::Certificate(cert) = item.context("invalid PEM")? {
                certs.push(cert);
            }
        }
        if certs.is_empty() {
            bail!("no certificate in {}", path.display());
        }
        config = config.tls_config(
            TlsConfig::builder()
                .root_certs(RootCerts::new_with_certs(&certs))
                .build(),
        );
    }
    Ok(config.build().new_agent())
}

/// Replaces `path` atomically: a failure leaves the previous file intact, and
/// a symbolic link at `path` is replaced rather than followed.
fn replace_file(path: &Path, content: &str) -> std::io::Result<()> {
    let temporary = with_suffix(path, &format!(".{}.tmp", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    // From here on the temporary file is ours to clean up.
    let result = file
        .write_all(content.as_bytes())
        .and_then(|()| std::fs::rename(&temporary, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// `path` with `suffix` appended to its file name.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    name.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_endpoint_from_safe_urls_only() {
        for (base, endpoint_url) in [
            ("https://ca.example.com", "https://ca.example.com/v1/certificates"),
            (
                "https://ca.example.com:8443/ssh/",
                "https://ca.example.com:8443/ssh/v1/certificates",
            ),
            ("http://localhost:8443", "http://localhost:8443/v1/certificates"),
            ("http://127.0.0.1/", "http://127.0.0.1/v1/certificates"),
            ("http://[::1]:80", "http://[::1]:80/v1/certificates"),
        ] {
            assert_eq!(endpoint(base, "certificates").unwrap(), endpoint_url);
        }
        for bad in [
            "http://ca.example.com",
            "http://localhost.example.com",
            "http://127.0.0.1.example.com",
            "http://localhost:password@198.51.100.5",
            "http://127.0.0.1:80@198.51.100.5",
            "http://[::1]@198.51.100.5",
            "https://user@ca.example.com",
            "https://ca.example.com/?x=1",
            "https://ca.example.com/#x",
            "ftp://localhost",
            "ca.example.com",
            "/v1",
        ] {
            assert!(endpoint(bad, "certificates").is_err(), "{bad}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn replaces_files_without_following_links() {
        let dir = std::env::temp_dir().join(format!("biscuit-ssh-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        std::fs::write(&target, "untouched").unwrap();
        let link = dir.join("id-cert.pub");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        replace_file(&link, "cert").unwrap();
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "cert");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");

        // A leftover temporary file is not ours: fail without touching it.
        let temporary = with_suffix(&link, &format!(".{}.tmp", std::process::id()));
        std::fs::write(&temporary, "sentinel").unwrap();
        assert!(replace_file(&link, "new").is_err());
        assert_eq!(std::fs::read_to_string(&temporary).unwrap(), "sentinel");
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "cert");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn derives_key_paths() {
        let identity = Path::new("/home/me/.ssh/id_ed25519");
        assert_eq!(with_suffix(identity, ".pub"), Path::new("/home/me/.ssh/id_ed25519.pub"));
        assert_eq!(
            with_suffix(identity, "-cert.pub"),
            Path::new("/home/me/.ssh/id_ed25519-cert.pub")
        );
    }
}
