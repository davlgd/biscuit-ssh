//! Creating, restricting and inspecting tokens.

use biscuit_auth::{Biscuit, BlockBuilder, KeyPair, UnverifiedBiscuit};

use crate::revocation::hex;
use crate::{Error, Restriction, Right};

/// Creates a token signed by the root key, granting `rights` under
/// `restrictions`.
pub fn mint(root: &KeyPair, rights: &[Right], restrictions: &[Restriction]) -> Result<String, Error> {
    if rights.is_empty() {
        return Err(Error::invalid("rights", "a token needs at least one right"));
    }
    let mut builder = Biscuit::builder();
    for right in rights {
        builder = builder.fact(right.to_fact()).map_err(Error::Datalog)?;
    }
    for restriction in restrictions {
        builder = builder.check(restriction.to_check()?).map_err(Error::Datalog)?;
    }
    builder
        .build(root)
        .and_then(|token| token.to_base64())
        .map_err(Error::Datalog)
}

/// Appends a block adding `restrictions` to `token`.
///
/// Needs no key: anyone holding a token can restrict it before handing it
/// over, and the result can never grant more than the original.
pub fn attenuate(token: &str, restrictions: &[Restriction]) -> Result<String, Error> {
    if restrictions.is_empty() {
        return Err(Error::invalid(
            "restrictions",
            "attenuating needs at least one restriction",
        ));
    }
    let token = UnverifiedBiscuit::from_base64(token.trim()).map_err(Error::InvalidToken)?;
    let mut block = BlockBuilder::new();
    for restriction in restrictions {
        block = block.check(restriction.to_check()?).map_err(Error::Datalog)?;
    }
    token
        .append(block)
        .and_then(|token| token.to_base64())
        .map_err(Error::Datalog)
}

/// One block of a token, as shown to humans.
#[derive(Debug)]
pub struct BlockInfo {
    /// Identifier to add to the revocation list to revoke this block (and
    /// every token derived from it).
    pub revocation_id: String,
    /// Datalog source of the block.
    pub source: String,
}

/// Decodes `token` without verifying its signature, to show its content.
pub fn inspect(token: &str) -> Result<Vec<BlockInfo>, Error> {
    let token = UnverifiedBiscuit::from_base64(token.trim()).map_err(Error::InvalidToken)?;
    token
        .revocation_identifiers()
        .iter()
        .enumerate()
        .map(|(index, id)| {
            let source = token.print_block_source(index).map_err(Error::InvalidToken)?;
            Ok(BlockInfo {
                revocation_id: hex(id),
                source,
            })
        })
        .collect()
}
