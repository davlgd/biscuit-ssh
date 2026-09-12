# AGENTS.md

Guidance for coding agents (and humans) working on this repository.

## Purpose

Give third parties SSH access to servers through [Biscuit](https://www.biscuitsec.org/) tokens, so access can be constrained by expiration, source IP, target server, account, command, etc. Token holders can attenuate their token offline and delegate it without involving us.

## Architecture

Servers only trust an OpenSSH user CA (`TrustedUserCAKeys` + `AuthorizedPrincipalsFile`). Nothing Biscuit-specific runs on them. Two ways to reach them, sharing the same authorization core:

- **Issuer**: a third party exchanges a Biscuit and an SSH public key for a short-lived OpenSSH certificate. Biscuit constraints are translated into certificate constraints enforced by `sshd` itself (`valid-before`, `source-address`, principals, `force-command`, `permit-*` extensions).
- **Bastion** (later): an SSH proxy that verifies the Biscuit at connection time, then reaches the target with an ephemeral certificate signed by the same CA. Used when in-session control is needed (per-command checks, cut at expiry, recording).

Cargo workspace layout:

```
crates/
├── core/      # fact vocabulary, verifier, token minting/attenuation, revocation, API messages (single source of truth)
├── ca/        # OpenSSH certificate signing, shared by issuer and bastion
├── issuer/    # binary `biscuit-ssh-issuer`: HTTP API, Biscuit → certificate
├── bastion/   # binary: SSH proxy verifying Biscuit (not started yet)
└── cli/       # binary `biscuit-ssh`: login, token attenuation/inspection, admin (root keys, minting)
tests/e2e.sh   # end-to-end scenarios against a real deployment
```

### Authorization model

Checks in a Biscuit are opaque predicates: never try to extract values from them. Instead, the verifier provides facts describing the actual request (`time`, `source_ip`, `source_net`, `server`, `user`, `command`, `public_key`, `mode`) and lets the token's checks and the verifier policies decide. Tokens grant access with `right($server, $user)` facts in their authority block; the default policy only trusts those.

The fact vocabulary, documented in `crates/core/src/vocabulary.rs`, is the public contract with token holders: changing it is a breaking change. Minting and attenuation only ever add `right` facts (authority block) and checks, never request facts.

A certificate is derived from an `Authorization` only, which embeds the request it was granted for: principal `server:user`, `source-address` pinned to the client address, `force-command` when requested. Its validity is never longer than what the token allows: the verifier evaluates the token at every second of the certificate lifetime (Biscuit dates have second resolution) and stops at the first refusal.

## Constraints

- **Rust edition 2024**, stable toolchain, workspace-level dependency versions (`[workspace.dependencies]`).
- **Dependencies up to date**: use the latest released version of every crate when adding it (check crates.io, don't rely on memory), and keep them current. Prefer few, well-maintained dependencies.
- **DRY / KISS / SOLID**: authorization logic lives only in `core`, signing only in `ca`; binaries stay thin. Choose the simplest design that works; no speculative abstraction.
- **Documentation and comments** are held to the same standard as code: clear, accurate, minimal.
  - Every public item has a doc comment explaining what it is for and any non-obvious behavior (errors, security implications, invariants).
  - Comments explain *why*, not *what*; add them where they help a reader (security reasoning, protocol quirks, non-obvious choices), and nowhere else.
  - Each crate has a crate-level doc (`//!`) describing its role. `README.md` covers usage and deployment, this file covers development.
  - Keep docs in sync with code in the same change.

## Security rules

- Fail closed: any parsing, verification or I/O error denies access.
- No `unwrap`/`expect`/`panic!` outside tests and provably infallible cases (justify those with a comment).
- Never log tokens, private keys or full certificates; log revocation IDs and key fingerprints instead.
- The CA private key is only ever loaded by `ca`; keep its handling isolated and auditable.
- Certificates are short-lived by default (120 s); revocation relies on Biscuit revocation IDs, checked at issuance, plus short lifetimes.
- Service logs and HTTP errors carry `Error::kind()` only: detailed Biscuit errors can quote Datalog written by the token holder.

## Workflow

Before considering a change done:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Security-sensitive code (authorization, signing, parsing untrusted input) needs tests covering both accepted and rejected cases.

Changes affecting what reaches `sshd` must also pass `tests/e2e.sh` against a test deployment (see its header). Run tests against a dedicated `sshd` instance, never the one you use to administer the test server.
