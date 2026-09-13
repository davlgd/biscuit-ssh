//! How the bastion asks for the token over keyboard-interactive, shared by
//! the bastion and the client.
//!
//! OpenSSH reads each answer (from a terminal or `SSH_ASKPASS`) into a
//! 1024-byte buffer, while tokens grow with every attenuation block. So the
//! token travels in parts: the bastion asks for part 1 with [`prompt`];
//! an answer ending with [`MORE`] means another part follows, which the
//! bastion asks for with the next prompt, up to [`MAX_TOKEN_LEN`] in all.
//! Tokens are base64url, so `MORE` never appears in them.

use crate::MAX_TOKEN_LEN;

/// Longest part sent in one answer, well below OpenSSH's limit.
pub const MAX_PART_LEN: usize = 1000;

/// Ends a part that is followed by another one.
pub const MORE: char = '+';

/// The most parts a token can take.
pub const MAX_PARTS: usize = MAX_TOKEN_LEN.div_ceil(MAX_PART_LEN);

/// The prompt asking for part `part` (from 1) of the token.
pub fn prompt(part: usize) -> String {
    match part {
        1 => "Biscuit token: ".to_owned(),
        n => format!("Biscuit token (part {n}): "),
    }
}

/// The part a prompt asks for, whether shown as is or prefixed with
/// `(login@host) ` as recent OpenSSH versions do. `None` for any other
/// prompt, which must never be answered with the token.
pub fn parse_prompt(prompt: &str) -> Option<usize> {
    let prompt = match prompt.strip_prefix('(') {
        Some(rest) => {
            let (login, rest) = rest.split_once(") ")?;
            if login.contains(['(', ')']) {
                return None;
            }
            rest
        }
        None => prompt,
    };
    (1..=MAX_PARTS).find(|&part| self::prompt(part) == prompt)
}

/// The answer to the prompt for part `part` of `token`: that part, followed
/// by [`MORE`] unless it is the last one. `None` past the last part.
pub fn answer(token: &str, part: usize) -> Option<String> {
    let start = part.checked_sub(1)?.checked_mul(MAX_PART_LEN)?;
    // Tokens are ASCII: byte offsets are character boundaries.
    let rest = token.get(start..).filter(|rest| !rest.is_empty())?;
    Some(match rest.get(..MAX_PART_LEN) {
        Some(part) if part.len() < rest.len() => format!("{part}{MORE}"),
        _ => rest.to_owned(),
    })
}

/// Rebuilds a token from the answers to successive prompts, refusing any
/// answer or total beyond the limits before storing it.
#[derive(Debug, Default)]
pub struct Assembly {
    token: String,
    parts: usize,
}

/// What an answer brought.
#[derive(Debug, PartialEq, Eq)]
pub enum Progress {
    /// Ask for this part next.
    Next(usize),
    /// The whole token.
    Done(String),
}

impl Assembly {
    /// Adds the answer to the latest prompt.
    pub fn push(&mut self, answer: &str) -> Result<Progress, crate::Error> {
        let (part, more) = match answer.strip_suffix(MORE) {
            Some(part) => (part, true),
            None => (answer, false),
        };
        self.parts += 1;
        if part.len() > MAX_PART_LEN
            || self.token.len() + part.len() > MAX_TOKEN_LEN
            || (more && self.parts >= MAX_PARTS)
        {
            return Err(crate::Error::InvalidInput {
                field: "token",
                reason: "too long",
            });
        }
        self.token.push_str(part);
        Ok(match more {
            true => Progress::Next(self.parts + 1),
            false => Progress::Done(std::mem::take(&mut self.token)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_token_prompts() {
        assert_eq!(parse_prompt("Biscuit token: "), Some(1));
        assert_eq!(
            parse_prompt("(deploy@web-1@bastion.example.com) Biscuit token: "),
            Some(1)
        );
        assert_eq!(parse_prompt("(deploy@web-1@bastion) Biscuit token (part 3): "), Some(3));
        for other in [
            "Enter passphrase for key 'id': ",
            "Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
            "Password: ",
            "Biscuit token:",
            "x Biscuit token: ",
            "(a) (b) Biscuit token: ",
            "Biscuit token (part 0): ",
            "Biscuit token (part 99): ",
            "Biscuit token: Biscuit token: ",
        ] {
            assert_eq!(parse_prompt(other), None, "{other}");
        }
    }

    #[test]
    fn splits_and_rebuilds_tokens() {
        for len in [
            1,
            MAX_PART_LEN - 1,
            MAX_PART_LEN,
            MAX_PART_LEN + 1,
            3 * MAX_PART_LEN + 7,
            MAX_TOKEN_LEN,
        ] {
            let token: String = (0..len).map(|i| char::from(b'A' + (i % 26) as u8)).collect();
            let mut rebuilt = String::new();
            for part in 1.. {
                let given = answer(&token, part).unwrap();
                assert!(given.len() <= MAX_PART_LEN + 1);
                match given.strip_suffix(MORE) {
                    Some(more) => rebuilt.push_str(more),
                    None => {
                        rebuilt.push_str(&given);
                        assert!(part <= MAX_PARTS);
                        assert_eq!(answer(&token, part + 1), None);
                        break;
                    }
                }
            }
            assert_eq!(rebuilt, token, "{len}");
        }
        assert_eq!(answer("abc", 0), None);
    }

    #[test]
    fn assembles_answers_within_limits() {
        let token = "T".repeat(2 * MAX_PART_LEN + 5);
        let mut assembly = Assembly::default();
        assert_eq!(assembly.push(&answer(&token, 1).unwrap()).unwrap(), Progress::Next(2));
        assert_eq!(assembly.push(&answer(&token, 2).unwrap()).unwrap(), Progress::Next(3));
        assert_eq!(
            assembly.push(&answer(&token, 3).unwrap()).unwrap(),
            Progress::Done(token)
        );

        let oversized = format!("{}{MORE}", "T".repeat(MAX_PART_LEN + 1));
        assert!(Assembly::default().push(&oversized).is_err());

        let mut endless = Assembly::default();
        let full = format!("{}{MORE}", "T".repeat(MAX_PART_LEN));
        let refused = (0..MAX_PARTS + 1).find(|_| endless.push(&full).is_err());
        assert!(refused.is_some(), "an endless token must be refused");
    }
}
