# AGENTS.md

Guidance for coding agents (and humans) working on this repository.

## Purpose

Give third parties SSH access to servers through [Biscuit](https://www.biscuitsec.org/) tokens, so access can be constrained by expiration, source IP, target server, account, command, etc. Token holders can attenuate their token offline and delegate it without involving us.

## Architecture

Servers only trust an OpenSSH user CA (`TrustedUserCAKeys` + `AuthorizedPrincipalsFile`). Nothing Biscuit-specific runs on them. Two ways to reach them, sharing the same authorization core:

- **Issuer**: a third party exchanges a Biscuit and an SSH public key for a short-lived OpenSSH certificate. Biscuit constraints are translated into certificate constraints enforced by `sshd` itself (`valid-before`, `source-address`, principals, `force-command`, `permit-*` extensions).
- **Bastion**: an SSH server that verifies the Biscuit at login (public key, then token through keyboard-interactive), then relays session channels to targets only it can reach, logging in with an ephemeral key and a certificate from the same CA pinned to its own address. It keeps re-evaluating the token (leases of `session_check_interval`): relaying stops at the exact second the token stops allowing access, or at the renewal that finds a revocation, and the sockets close at most 2 seconds later. It can also run sessions in Docker containers (`[containers]`, unreleased), through `docker exec`, with a root key and revocation list of their own. Per-command control and session recording come next.

**Sandbox** (`sandbox/`, unreleased): a separate application on top of biscuit-ssh, a REST service creating disposable containers from Docker Hub images, reachable only through the bastion with a token restricted to the requester's address; a container lives as long as its token. See `sandbox/README.md`.

Cargo workspace layout:

```
crates/
├── core/      # fact vocabulary, verifier, token minting/attenuation, revocation, issuer API messages, bastion login prompts
├── ca/        # OpenSSH certificate signing, shared by issuer and bastion
├── service/   # plumbing shared by the services: authority (verifier, CA, revocations), logging, shutdown
├── issuer/    # binary `biscuit-ssh-issuer`: HTTP API, Biscuit → certificate
├── bastion/   # binary `biscuit-ssh-bastion`: token-checked SSH relay (russh)
└── cli/       # binary `biscuit-ssh`: login, ssh (direct or through the bastion), token attenuation/inspection, admin
tests/e2e.sh   # end-to-end scenarios against a real deployment
sandbox/       # separate Cargo workspace (own Cargo.lock and target): the sandbox service and its e2e tests
CHANGELOG.md   # user-facing changes; unreleased ones under "Unreleased"
```

### Authorization model

Checks in a Biscuit are opaque predicates: never try to extract values from them. Instead, the verifier provides facts describing the actual request (`time`, `source_ip`, `source_net`, `server`, `user`, `command`, `public_key`, `mode`) and lets the token's checks and the verifier policies decide. Tokens grant access with `right($server, $user)` facts in their authority block; the default policy only trusts those.

The fact vocabulary, documented in `crates/core/src/vocabulary.rs`, is the public contract with token holders: changing it is a breaking change. Minting and attenuation only ever add `right` facts (authority block) and checks, never request facts.

A certificate is derived from an `Authorization` only, which embeds the request it was granted for: principal `server:user`, `source-address` pinned to the client address (or to the bastion's, for relayed logins), `force-command` when requested. Its validity is never longer than what the token allows: the verifier evaluates the token at every second of the certificate lifetime (Biscuit dates have second resolution) and stops at the first refusal. The bastion applies the same rule to live connections, one lease after another.

### Bastion invariants

- Requests from the client are handled in russh handler callbacks that wait for the target's answer before replying: russh keeps a single pending-reply flag per channel.
- Handler callbacks wrap their waits in `access::until_cut`, and relay tasks watch the cut flag; what they may still be blocked on ends when the cut closes the client and target sockets themselves, after a short graceful window. Closing sockets is the guarantee, since russh sessions run in background tasks that a stalled peer could keep alive.
- The token reaches the bastion in parts (`core::bastion_login`): OpenSSH caps each keyboard-interactive answer at 1023 bytes, below attenuated tokens.
- russh uses `ssh-key` 0.7 while the CA uses 0.6: keys and certificates cross over in OpenSSH text format, in `target.rs` only.
- The target kind (server or container) is resolved before the token is checked, and selects the root key and revocation list: never fall back from one kind to the other. Containers are then addressed by their immutable ID.
- Container sessions (`container.rs`): one `exec` per channel; with a terminal, client EOF is ignored (Docker would hang the terminal up), as sshd does. Docker cannot stop an exec: only removing the container stops its commands.

### Sandbox invariants

- `state.json` is the single source of truth, written atomically (and the revocation list, a projection of it, rewritten after each change) before any effect relying on it; one instance per state directory (file lock).
- Lifecycle: `Creating` (persisted before pulling) → `Active` → `Deleting`; startup undoes `Creating` and completes `Deleting`; the reaper removes expired sandboxes, containers of this instance the state does not know, and forgets vanished ones. Containers are acted on by ID; names are only looked up with the instance label.
- Tokens expire at `expires_at - 1` (Biscuit expirations are inclusive), containers are removed from `expires_at`.
- Every request from a non-allowed address gets the same 401 before its body is read; errors never carry Docker's messages; tokens appear only in create/renew responses, never in logs or listings.

## Constraints

- **Rust edition 2024**, stable toolchain, workspace-level dependency versions (`[workspace.dependencies]`).
- **Dependencies up to date**: use the latest released version of every crate when adding it (check crates.io, don't rely on memory), and keep them current. Prefer few, well-maintained dependencies.
- **DRY / KISS / SOLID**: authorization logic lives only in `core`, signing only in `ca`; binaries stay thin. Choose the simplest design that works; no speculative abstraction.
- **Documentation and comments** are held to the same standard as code: clear, accurate, minimal.
  - Every public item has a doc comment explaining what it is for and any non-obvious behavior (errors, security implications, invariants).
  - Comments explain *why*, not *what*; add them where they help a reader (security reasoning, protocol quirks, non-obvious choices), and nowhere else.
  - Each crate has a crate-level doc (`//!`) describing its role. `README.md` covers usage and deployment, this file covers development.
  - Keep docs in sync with code in the same change, and record user-facing changes in `CHANGELOG.md` (under "Unreleased" until a release).

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
(cd sandbox && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test)
```

Security-sensitive code (authorization, signing, parsing untrusted input) needs tests covering both accepted and rejected cases.

Changes affecting what reaches `sshd` must also pass `tests/e2e.sh` against a test deployment, and changes to the sandbox or to container sessions `sandbox/tests/e2e.sh` (see their headers). Run tests against a dedicated `sshd` instance, never the one you use to administer the test server, and never commit the addresses, host names or paths of a real deployment.
