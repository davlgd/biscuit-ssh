//! Docker Hub image references.
//!
//! Only Docker Hub images are accepted: a reference naming another registry,
//! or carrying anything but a repository, a tag and a digest, is refused
//! before Docker sees it.

use std::fmt;
use std::str::FromStr;

/// A Docker Hub image: `[docker.io/][namespace/]repository[:tag][@sha256:…]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    /// `namespace/repository`, `library/` for official images.
    repository: String,
    /// Tag, `latest` unless a digest is given.
    tag: Option<String>,
    /// `sha256:…` digest, pinning the image.
    digest: Option<String>,
}

/// Why a reference is not a valid Docker Hub image reference.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum InvalidImage {
    /// It names another registry.
    #[error("only Docker Hub images are accepted")]
    OtherRegistry,
    /// Its repository has uppercase letters.
    #[error("repository names must be lowercase")]
    Uppercase,
    /// Anything else.
    #[error("expected [namespace/]repository[:tag][@sha256:digest]")]
    Malformed,
}

impl ImageRef {
    /// The image to pull, without tag or digest: `docker.io/library/nginx`.
    pub fn repository(&self) -> String {
        format!("docker.io/{}", self.repository)
    }

    /// The tag or digest to pull.
    pub fn version(&self) -> &str {
        self.digest.as_deref().or(self.tag.as_deref()).unwrap_or("latest")
    }
}

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "docker.io/{}", self.repository)?;
        match (&self.tag, &self.digest) {
            (_, Some(digest)) => write!(f, "@{digest}"),
            (Some(tag), None) => write!(f, ":{tag}"),
            (None, None) => write!(f, ":latest"),
        }
    }
}

impl FromStr for ImageRef {
    type Err = InvalidImage;

    fn from_str(s: &str) -> Result<Self, InvalidImage> {
        if s.len() > 255 {
            return Err(InvalidImage::Malformed);
        }
        let (rest, digest) = match s.split_once('@') {
            Some((rest, digest)) => (rest, Some(digest)),
            None => (s, None),
        };
        if let Some(digest) = digest {
            let hex = digest.strip_prefix("sha256:").ok_or(InvalidImage::Malformed)?;
            if hex.len() != 64 || !hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                return Err(InvalidImage::Malformed);
            }
        }
        // A tag follows the last colon after the last slash.
        let (path, tag) = match rest.rsplit_once(':') {
            Some((path, tag)) if !tag.contains('/') => (path, Some(tag)),
            _ => (rest, None),
        };
        if let Some(tag) = tag {
            let valid = tag.len() <= 128
                && tag.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
                && tag
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
            if !valid {
                return Err(InvalidImage::Malformed);
            }
        }
        let path = path
            .strip_prefix("docker.io/")
            .or_else(|| path.strip_prefix("index.docker.io/"))
            .unwrap_or(path);
        let components: Vec<&str> = path.split('/').collect();
        // Other registries are named by a first component with a dot, a colon
        // or `localhost`; Docker Hub repositories have at most a namespace.
        if let [first, _, ..] = components.as_slice()
            && (first.contains(['.', ':']) || *first == "localhost")
        {
            return Err(InvalidImage::OtherRegistry);
        }
        if components.len() > 2 {
            return Err(InvalidImage::Malformed);
        }
        if !components.iter().all(|c| is_component(c)) {
            let lowercase = components.iter().all(|c| is_component(&c.to_ascii_lowercase()));
            return Err(if lowercase {
                InvalidImage::Uppercase
            } else {
                InvalidImage::Malformed
            });
        }
        let repository = match components.as_slice() {
            [name] => format!("library/{name}"),
            _ => path.to_owned(),
        };
        Ok(Self {
            repository,
            tag: tag.map(str::to_owned),
            digest: digest.map(str::to_owned),
        })
    }
}

/// A path component: lowercase letters and digits, separated by `.`, `_`,
/// `__` or dashes.
fn is_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    let alnum = |b: &u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    !bytes.is_empty()
        && bytes.first().is_some_and(alnum)
        && bytes.last().is_some_and(alnum)
        && bytes.iter().all(|b| alnum(b) || matches!(b, b'.' | b'_' | b'-'))
        && !component.contains("..")
        && !component.contains("___")
        && !component.contains("._")
        && !component.contains("_.")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical(s: &str) -> String {
        s.parse::<ImageRef>().unwrap().to_string()
    }

    #[test]
    fn canonicalizes_docker_hub_references() {
        assert_eq!(canonical("alpine"), "docker.io/library/alpine:latest");
        assert_eq!(canonical("alpine:3.20"), "docker.io/library/alpine:3.20");
        assert_eq!(canonical("docker.io/library/alpine"), "docker.io/library/alpine:latest");
        assert_eq!(canonical("bitnami/redis:7.4"), "docker.io/bitnami/redis:7.4");
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            canonical(&format!("alpine@{digest}")),
            format!("docker.io/library/alpine@{digest}")
        );
        let pinned: ImageRef = format!("alpine:3@{digest}").parse().unwrap();
        assert_eq!(pinned.repository(), "docker.io/library/alpine");
        assert_eq!(pinned.version(), digest);
    }

    #[test]
    fn refuses_other_registries_and_malformed_references() {
        for (bad, why) in [
            ("ghcr.io/owner/image", InvalidImage::OtherRegistry),
            ("localhost/image", InvalidImage::OtherRegistry),
            ("registry:5000/image", InvalidImage::OtherRegistry),
            ("Alpine:Latest", InvalidImage::Uppercase),
            ("a/b/c", InvalidImage::Malformed),
        ] {
            assert_eq!(bad.parse::<ImageRef>().err(), Some(why), "{bad}");
        }
        for bad in [
            "",
            "alpine:",
            "alpine:-tag",
            "alpine@sha256:abc",
            "alpine@md5:0",
            "alpine;rm -rf /",
            "--help",
            "../etc",
            "a..b",
        ] {
            assert!(bad.parse::<ImageRef>().is_err(), "{bad}");
        }
    }
}
