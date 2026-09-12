use std::collections::HashSet;

use crate::Error;

/// Shortest accepted identifier, in hex characters (32 bytes).
const MIN_ID_LEN: usize = 64;

/// Revoked block identifiers, as lowercase hex strings.
///
/// Identifiers are block signatures (64 bytes for Ed25519). Shorter entries
/// are refused, so a truncated copy fails loudly instead of revoking nothing.
///
/// Every block of a token has its own revocation identifier, and revoking
/// any of them revokes the token and every token derived from it by
/// attenuation. `biscuit-ssh token inspect` prints them.
#[derive(Debug, Clone, Default)]
pub struct RevocationList(HashSet<String>);

impl RevocationList {
    /// Parses one hex identifier per line; blank lines and lines starting
    /// with `#` are ignored.
    pub fn parse(text: &str) -> Result<Self, Error> {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| {
                if line.len() < MIN_ID_LEN || line.len() % 2 != 0 || !line.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(Error::invalid(
                        "revocation identifier",
                        "expected at least 32 hex-encoded bytes",
                    ));
                }
                Ok(line.to_ascii_lowercase())
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }

    /// The first of `ids` that is revoked, if any.
    pub(crate) fn find<'a>(&self, ids: &'a [String]) -> Option<&'a String> {
        ids.iter().find(|id| self.0.contains(*id))
    }
}

/// Lowercase hex encoding, matching [`RevocationList`] entries.
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_identifiers() {
        let (a, b) = ("ab".repeat(64), "cd".repeat(64));
        let list = RevocationList::parse(&format!("# revoked\n\n{}\n  {b} \n", a.to_uppercase())).unwrap();
        let ids = ["ef".repeat(64), a];
        assert_eq!(list.find(&ids), Some(&ids[1]));
        assert_eq!(list.find(&ids[..1]), None);
    }

    #[test]
    fn rejects_malformed_identifiers() {
        for bad in ["abcd".to_owned(), "a".repeat(129), "z".repeat(128)] {
            assert!(RevocationList::parse(&bad).is_err(), "{bad}");
        }
    }
}
