use std::time::{Duration, Instant};

use biscuit_auth::error::{Logic, RunLimit, Token as TokenError};
use biscuit_auth::{AuthorizerBuilder, AuthorizerLimits, Biscuit, PublicKey};

use crate::revocation::hex;
use crate::vocabulary::{request_facts, time_fact, unix_seconds};
use crate::{AccessRequest, Error, RevocationList};

/// Grants a request when the token holds the matching `right` in its
/// authority block. Facts added by attenuation blocks are not visible to
/// verifier policies, so a holder cannot grant themselves new rights.
pub const DEFAULT_POLICY: &str = "allow if server($s), user($u), right($s, $u);";

/// Longest accepted token, in base64 characters. Real tokens are a few
/// hundred bytes per block; the limit bounds parsing work on hostile input.
pub const MAX_TOKEN_LEN: usize = 16 * 1024;

/// Longest lifetime [`Verifier::authorize`] accepts, as it evaluates the
/// token once per second of it.
pub const MAX_LIFETIME: Duration = Duration::from_secs(600);

/// Bounds each Datalog evaluation so a crafted token cannot exhaust the
/// verifier. A request contributes at most ~140 facts (mostly `source_net`
/// for IPv6).
const LIMITS: AuthorizerLimits = AuthorizerLimits {
    max_facts: 1_000,
    max_iterations: 100,
    max_time: Duration::from_millis(20),
};

/// Bounds the total time [`Verifier::authorize`] spends on one request.
const BUDGET: Duration = Duration::from_millis(500);

/// Decides whether a token allows an access request, and for how long.
#[derive(Debug, Clone)]
pub struct Verifier {
    root_key: PublicKey,
    policies: AuthorizerBuilder,
}

/// A successful authorization: the request it was granted for, and for how
/// long.
///
/// Only [`Verifier::authorize`] creates it, so holding one proves that this
/// exact request was checked; credentials must be derived from it alone.
#[derive(Debug)]
pub struct Authorization {
    request: AccessRequest,
    revocation_ids: Vec<String>,
    valid_from: u64,
    valid_until: u64,
}

impl Authorization {
    /// The request that was authorized.
    pub fn request(&self) -> &AccessRequest {
        &self.request
    }

    /// Revocation identifiers of the token's blocks, in order, the authority
    /// block first.
    pub fn revocation_ids(&self) -> &[String] {
        &self.revocation_ids
    }

    /// Revocation identifier of the token's last block, which names the
    /// exact token presented (its ancestors have the earlier ones). Logged by
    /// the services and used as certificate key ID.
    pub fn token_id(&self) -> &str {
        // A token always has at least its authority block.
        self.revocation_ids.last().map_or("", String::as_str)
    }

    /// Start of the validity window: the request time, in seconds since the
    /// Unix epoch.
    pub fn valid_from(&self) -> u64 {
        self.valid_from
    }

    /// End of the validity window (exclusive), in seconds since the Unix
    /// epoch: the token allows the request at every second from
    /// [`Self::valid_from`] up to, not including, this one.
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
}

impl Verifier {
    /// Creates a verifier accepting tokens signed by `root_key`, and applying
    /// `policies` (Datalog policies, see [`DEFAULT_POLICY`]).
    pub fn new(root_key: PublicKey, policies: &str) -> Result<Self, Error> {
        let policies = AuthorizerBuilder::new()
            .code(policies)
            .map_err(Error::Datalog)?
            .set_limits(LIMITS);
        Ok(Self { root_key, policies })
    }

    /// The root public key tokens must be signed with.
    pub fn root_key(&self) -> PublicKey {
        self.root_key
    }

    /// Checks that `token` allows `request`, and finds how long it keeps
    /// allowing it, up to `lifetime`.
    ///
    /// Token checks are arbitrary Datalog, so the expiry cannot be read from
    /// them. Instead the request is evaluated at each second (the resolution
    /// of Biscuit dates) from `request.time`, and the window stops at the
    /// first refusal: credentials bounded by [`Authorization::valid_until`]
    /// never outlive what the token allows, whatever its time checks are.
    ///
    /// Only a policy refusal ends the window; any other failure (execution
    /// limits, Datalog errors) rejects the whole request.
    pub fn authorize(
        &self,
        token: &str,
        request: &AccessRequest,
        revoked: &RevocationList,
        lifetime: Duration,
    ) -> Result<Authorization, Error> {
        let deadline = Instant::now() + BUDGET;
        if lifetime < Duration::from_secs(1) || lifetime > MAX_LIFETIME {
            return Err(Error::invalid("lifetime", "must be between 1 second and 10 minutes"));
        }
        let start = unix_seconds(request.time)?;
        let token = token.trim();
        if token.len() > MAX_TOKEN_LEN {
            return Err(Error::invalid("token", "too long"));
        }
        let token = Biscuit::from_base64(token, self.root_key).map_err(Error::InvalidToken)?;

        let revocation_ids: Vec<String> = token.revocation_identifiers().iter().map(|id| hex(id)).collect();
        if let Some(id) = revoked.find(&revocation_ids) {
            return Err(Error::Revoked(id.clone()));
        }

        let mut context = self.policies.clone();
        for fact in request_facts(request) {
            context = context.fact(fact).map_err(Error::Datalog)?;
        }
        let evaluate = |second| context.clone().fact(time_fact(second))?.build(&token)?.authorize();

        evaluate(start).map_err(refusal)?;
        let end = start
            .checked_add(lifetime.as_secs())
            .ok_or(Error::invalid("time", "too far in the future"))?;
        let mut valid_until = end;
        for second in start + 1..end {
            if Instant::now() > deadline {
                return Err(Error::Overloaded);
            }
            match evaluate(second) {
                Ok(_) => {}
                Err(TokenError::FailedLogic(Logic::Unauthorized { .. } | Logic::NoMatchingPolicy { .. })) => {
                    valid_until = second;
                    break;
                }
                Err(e) => return Err(refusal(e)),
            }
        }
        Ok(Authorization {
            request: request.clone(),
            revocation_ids,
            valid_from: start,
            valid_until,
        })
    }
}

/// The error for a failed evaluation.
///
/// Running out of time may come from the load, so it is told apart from a
/// refusal: the issuer answers it as a temporary failure, and the bastion
/// retries while the lease lasts. Too many facts or iterations depend on the
/// token alone, and stay a refusal.
fn refusal(error: TokenError) -> Error {
    match error {
        TokenError::RunLimit(RunLimit::Timeout) => Error::Overloaded,
        error => Error::Denied(error),
    }
}

/// The token's own checks refusing `request`, as a hint to explain a
/// refusal to the token holder.
///
/// Only the token's checks are evaluated, under a policy allowing anything:
/// the verifier's policies, and any facts or rules they add, are unknown to
/// the caller and never involved. An empty result only means that no token
/// check fails in this context, not why the verifier refused. The returned
/// checks quote the token's Datalog: show them to its holder, never log them.
pub fn failed_checks(root_key: PublicKey, token: &str, request: &AccessRequest) -> Result<Vec<String>, Error> {
    let verifier = Verifier::new(root_key, "allow if true;")?;
    let result = verifier.authorize(token, request, &RevocationList::default(), Duration::from_secs(1));
    match result {
        Ok(_) => Ok(Vec::new()),
        Err(Error::Denied(TokenError::FailedLogic(
            Logic::Unauthorized { checks, .. } | Logic::NoMatchingPolicy { checks },
        ))) => Ok(checks.iter().map(ToString::to_string).collect()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use biscuit_auth::{BlockBuilder, KeyPair, UnverifiedBiscuit};

    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::{Mode, Network, Restriction, Right, attenuate, mint};

    const KEY: &str = "SHA256:test";
    const LIFETIME: Duration = Duration::from_secs(120);
    /// A fixed request time: tokens are evaluated against request facts,
    /// never against the wall clock.
    const T0: u64 = 2_000_000_000;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(seconds)
    }

    fn request(server: &str, user: &str, ip: &str) -> AccessRequest {
        AccessRequest {
            time: at(T0),
            source_ip: ip.parse().unwrap(),
            server: server.parse().unwrap(),
            user: user.parse().unwrap(),
            command: None,
            public_key: KEY.to_owned(),
            mode: Mode::Certificate,
        }
    }

    fn setup(restrictions: &[Restriction]) -> (Verifier, KeyPair, String) {
        let root = KeyPair::new();
        let rights: Vec<Right> = vec!["web-1:deploy".parse().unwrap(), "web-2:admin".parse().unwrap()];
        let token = mint(&root, &rights, restrictions).unwrap();
        (Verifier::new(root.public(), DEFAULT_POLICY).unwrap(), root, token)
    }

    fn authorize(verifier: &Verifier, token: &str, request: &AccessRequest) -> Result<Authorization, Error> {
        verifier.authorize(token, request, &RevocationList::default(), LIFETIME)
    }

    fn allowed(verifier: &Verifier, token: &str, request: &AccessRequest) -> bool {
        authorize(verifier, token, request).is_ok()
    }

    /// Appends raw Datalog to a token, as a malicious holder could.
    fn append_code(token: &str, code: &str) -> String {
        let block = BlockBuilder::new().code(code).unwrap();
        let token = UnverifiedBiscuit::from_base64(token).unwrap();
        token.append(block).unwrap().to_base64().unwrap()
    }

    #[test]
    fn tells_overload_from_refusal() {
        assert!(matches!(
            refusal(TokenError::RunLimit(RunLimit::Timeout)),
            Error::Overloaded
        ));
        assert_eq!(Error::Overloaded.kind(), "overloaded");
        for limit in [RunLimit::TooManyFacts, RunLimit::TooManyIterations] {
            assert!(matches!(refusal(TokenError::RunLimit(limit)), Error::Denied(_)));
        }
    }

    #[test]
    fn explains_refusals_with_the_token_checks_only() {
        let (v, _, token) = setup(&[Restriction::Servers(vec!["web-2".parse().unwrap()])]);
        let failed = failed_checks(v.root_key(), &token, &request("web-1", "deploy", "192.0.2.7")).unwrap();
        assert_eq!(failed.len(), 1);
        assert!(failed[0].contains("web-2"), "{failed:?}");

        // No token check fails: the refusal comes from the policy (no right).
        let failed = failed_checks(v.root_key(), &token, &request("web-2", "deploy", "192.0.2.7")).unwrap();
        assert!(failed.is_empty());
        assert!(!allowed(&v, &token, &request("web-2", "deploy", "192.0.2.7")));
    }

    #[test]
    fn lists_only_authority_rights() {
        let (v, _, token) = setup(&[]);
        let forged = append_code(&token, r#"right("web-9", "root");"#);
        let rights: Vec<String> = crate::granted_rights(v.root_key(), &forged)
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(rights, ["web-1:deploy", "web-2:admin"]);
        let (_, other_root, _) = setup(&[]);
        assert!(crate::granted_rights(other_root.public(), &token).is_err());
    }

    #[test]
    fn grants_only_listed_rights() {
        let (v, _, token) = setup(&[]);
        assert!(allowed(&v, &token, &request("web-1", "deploy", "192.0.2.7")));
        assert!(allowed(&v, &token, &request("web-2", "admin", "192.0.2.7")));
        assert!(!allowed(&v, &token, &request("web-1", "admin", "192.0.2.7")));
        assert!(!allowed(&v, &token, &request("web-3", "deploy", "192.0.2.7")));
    }

    #[test]
    fn rejects_foreign_corrupt_or_oversized_tokens() {
        let (v, _, _) = setup(&[]);
        let (_, _, foreign) = setup(&[]);
        let req = request("web-1", "deploy", "192.0.2.7");
        assert!(matches!(authorize(&v, &foreign, &req), Err(Error::InvalidToken(_))));
        assert!(matches!(authorize(&v, "garbage", &req), Err(Error::InvalidToken(_))));
        let huge = "A".repeat(MAX_TOKEN_LEN + 1);
        assert!(matches!(authorize(&v, &huge, &req), Err(Error::InvalidInput { .. })));
    }

    #[test]
    fn rejects_invalid_times_and_lifetimes() {
        let (v, _, token) = setup(&[]);
        let mut req = request("web-1", "deploy", "192.0.2.7");
        let none = RevocationList::default();
        for lifetime in [
            Duration::ZERO,
            Duration::from_millis(999),
            MAX_LIFETIME + Duration::from_secs(1),
        ] {
            assert!(matches!(
                v.authorize(&token, &req, &none, lifetime),
                Err(Error::InvalidInput { .. })
            ));
        }
        req.time = UNIX_EPOCH - Duration::from_secs(1);
        assert!(matches!(authorize(&v, &token, &req), Err(Error::InvalidInput { .. })));
        assert!(Restriction::ExpiresAt(req.time).to_check().is_err());
    }

    #[test]
    fn window_is_capped_by_expiration() {
        let req = request("web-1", "deploy", "192.0.2.7");

        let (v, _, token) = setup(&[]);
        assert_eq!(authorize(&v, &token, &req).unwrap().valid_until(), T0 + 120);

        let (v, _, token) = setup(&[Restriction::ExpiresAt(at(T0 + 30))]);
        assert_eq!(authorize(&v, &token, &req).unwrap().valid_until(), T0 + 31);

        let (v, _, token) = setup(&[Restriction::ExpiresAt(at(T0 - 1))]);
        assert!(matches!(authorize(&v, &token, &req), Err(Error::Denied(_))));
    }

    #[test]
    fn window_stops_at_first_refusal() {
        let (v, _, token) = setup(&[]);
        let gap = format!(
            "check if time($t), $t < {} or time($t), $t > {};",
            rfc3339(T0 + 10),
            rfc3339(T0 + 20)
        );
        let token = append_code(&token, &gap);
        let req = request("web-1", "deploy", "192.0.2.7");
        assert_eq!(authorize(&v, &token, &req).unwrap().valid_until(), T0 + 10);
    }

    #[test]
    fn forged_facts_do_not_bypass_earlier_checks() {
        let (v, _, token) = setup(&[
            Restriction::ExpiresAt(at(T0 - 1)),
            Restriction::Servers(vec!["web-2".parse().unwrap()]),
        ]);
        let forged = append_code(&token, &format!(r#"time({}); server("web-2");"#, rfc3339(T0 - 10)));
        assert!(!allowed(&v, &forged, &request("web-2", "admin", "192.0.2.7")));
    }

    #[test]
    fn enforces_source_networks() {
        let nets = vec![
            "192.0.2.0/24".parse().unwrap(),
            "2001:db8::/32".parse::<Network>().unwrap(),
        ];
        let (v, _, token) = setup(&[Restriction::SourceNetworks(nets)]);
        assert!(allowed(&v, &token, &request("web-1", "deploy", "192.0.2.7")));
        assert!(allowed(&v, &token, &request("web-1", "deploy", "::ffff:192.0.2.7")));
        assert!(allowed(&v, &token, &request("web-1", "deploy", "2001:db8::1")));
        assert!(!allowed(&v, &token, &request("web-1", "deploy", "198.51.100.1")));
    }

    #[test]
    fn host_networks_match_whatever_the_spelling() {
        for (restriction, client) in [
            ("::ffff:192.0.2.7", "192.0.2.7"),
            ("192.0.2.7", "::ffff:192.0.2.7"),
            ("::ffff:192.0.2.7/128", "192.0.2.7"),
            ("2001:DB8:0::1", "2001:db8::1"),
            ("2001:db8::1/128", "2001:db8::1"),
        ] {
            let (v, _, token) = setup(&[Restriction::SourceNetworks(vec![restriction.parse().unwrap()])]);
            assert!(
                allowed(&v, &token, &request("web-1", "deploy", client)),
                "{restriction} vs {client}"
            );
        }
    }

    #[test]
    fn enforces_commands_and_keys() {
        let (v, _, token) = setup(&[
            Restriction::Commands(vec!["uptime".parse().unwrap()]),
            Restriction::PublicKeys(vec![KEY.to_owned()]),
        ]);
        let mut req = request("web-1", "deploy", "192.0.2.7");
        assert!(!allowed(&v, &token, &req), "an interactive session must be refused");
        req.command = Some("uptime".parse().unwrap());
        assert!(allowed(&v, &token, &req));
        req.command = Some("reboot".parse().unwrap());
        assert!(!allowed(&v, &token, &req));
        req.command = Some("uptime".parse().unwrap());
        req.public_key = "SHA256:other".to_owned();
        assert!(!allowed(&v, &token, &req));
    }

    #[test]
    fn attenuation_only_narrows() {
        let (v, _, token) = setup(&[]);
        let narrowed = attenuate(&token, &[Restriction::Servers(vec!["web-2".parse().unwrap()])]).unwrap();
        assert!(allowed(&v, &narrowed, &request("web-2", "admin", "192.0.2.7")));
        assert!(!allowed(&v, &narrowed, &request("web-1", "deploy", "192.0.2.7")));

        // A right asserted by an attenuation block is ignored by the policy.
        let forged = append_code(&token, r#"right("web-9", "root");"#);
        assert!(!allowed(&v, &forged, &request("web-9", "root", "192.0.2.7")));
    }

    #[test]
    fn honors_revocation() {
        let (v, _, token) = setup(&[]);
        let narrowed = attenuate(&token, &[Restriction::Mode(Mode::Certificate)]).unwrap();
        let req = request("web-1", "deploy", "192.0.2.7");
        let auth = authorize(&v, &narrowed, &req).unwrap();
        assert_eq!(auth.valid_from(), T0);
        assert_eq!(auth.token_id(), auth.revocation_ids()[1]);
        let ids = auth.revocation_ids();
        assert_eq!(ids.len(), 2);

        // Revoking the root block revokes every derived token.
        let revoked = RevocationList::parse(&ids[0]).unwrap();
        for token in [&narrowed, &token] {
            assert!(matches!(
                v.authorize(token, &req, &revoked, LIFETIME),
                Err(Error::Revoked(_))
            ));
        }
    }

    /// Formats a Biscuit date literal.
    fn rfc3339(seconds: u64) -> String {
        let check = Restriction::ExpiresAt(at(seconds)).to_check().unwrap().to_string();
        // "check if time($t), $t <= <date>"
        check.rsplit(' ').next().unwrap().to_owned()
    }
}
