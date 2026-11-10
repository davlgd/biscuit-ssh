# Contributing

This guide explains how biscuit-ssh works, which rules its code follows, and how to check and submit a change. People and agents follow it alike, and [AGENTS.md](https://github.com/davlgd/biscuit-ssh/blob/main/AGENTS.md) adds what agents check before reporting a change as done.

## Architecture

Servers only trust an OpenSSH user CA, through `TrustedUserCAKeys` and `AuthorizedPrincipalsFile`: nothing specific to Biscuit runs on them. The issuer exchanges a token and an SSH public key for a short-lived certificate. The bastion checks a token at login, then relays sessions to servers only it can reach, or into Docker containers. Both share the same authorization core.

The repository is a Cargo workspace:

| Path             | Role                                                                                        |
| ---------------- | ------------------------------------------------------------------------------------------- |
| `crates/bastion` | `biscuit-ssh-bastion`: the SSH relay that checks tokens, built on russh                     |
| `crates/ca`      | OpenSSH certificate signing, shared by the issuer and the bastion                           |
| `crates/cli`     | `biscuit-ssh`: connection, token attenuation and inspection, and administration             |
| `crates/core`    | Fact vocabulary, verifier, token minting and attenuation, revocation, and protocol messages |
| `crates/issuer`  | `biscuit-ssh-issuer`: the HTTP API that exchanges tokens for certificates                   |
| `crates/service` | Plumbing shared by the services: logging, shutdown, and the `authority` and `http` features |
| `tests/e2e.sh`   | End-to-end scenarios against a real deployment                                              |

In the client, `bastion.rs` and `certificate.rs` hold what each way in needs. The `certificates` feature, off by default, builds the second one: without it, the client only connects through the bastion, and has no HTTP or TLS dependency. A plain `cargo build` also leaves the issuer out, as `default-members` sets. In `service`, the `authority` feature holds the token verifier and the certificate signer of the issuer and the bastion. The sandbox service only needs `http`, and thus builds without the CA.

### Authorization model

The checks of a Biscuit are opaque predicates: never try to extract values from them. The verifier provides facts that describe the actual request instead, and lets the checks of the token and the policies of the verifier decide. These facts are `time`, `source_ip`, `source_net`, `server`, `user`, `command`, `public_key`, and `mode`.

Tokens grant access with `right($server, $user)` facts in their authority block, and the default policy only trusts those. Minting and attenuation only ever add `right` facts, in the authority block, and checks: never request facts.

The fact vocabulary, in [`crates/core/src/vocabulary.rs`](https://github.com/davlgd/biscuit-ssh/blob/main/crates/core/src/vocabulary.rs), is the public contract with token holders. Renaming a fact or changing its arity breaks every token in circulation.

### Certificates

A certificate derives from an `Authorization` only, which embeds the request the verifier granted. Its principal is `server:user`. Its `source-address` is the client address, or the address of the bastion for relayed logins. It carries `force-command` when the request has a command.

A certificate is never valid longer than what its token allows. Biscuit dates have a resolution of one second, so the verifier evaluates the token at every second of the certificate lifetime. It stops at the first refusal. The bastion applies the same rule to open connections, one lease of `session_check_interval` after another. A check that times out may come from the load: it's `Error::Overloaded`, not a refusal. The issuer answers `503`, and the bastion retries it, never beyond the current lease.

### Bastion

The bastion handles client requests in russh handler callbacks, which wait for the answer of the target before they reply. russh keeps a single pending-reply flag per channel. Handler callbacks wrap their waits in `access::until_cut`, and relay tasks watch the cut flag.

A cut closes the client and target sockets after a short graceful window, ending whatever the bastion still waits for. Closing sockets is the guarantee, because russh sessions run in background tasks a stalled peer could keep alive.

The token reaches the bastion in parts, through `core::bastion_login`: OpenSSH caps each keyboard-interactive answer at 1,023 bytes, below the size of attenuated tokens. When the token alone doesn't allow a login, the bastion asks for a command, and checks the token with it. The grant of the connection, and its certificate, then carry this command for its whole life. The client restricts the token to `--command`, and disables multiplexing, so that a command always reaches the bastion.

The bastion resolves the kind of a target, server or container, before it checks the token. The kind selects the root key and the revocation list, never falling back from one kind to the other. Containers go by their immutable ID.

Container sessions, in `container.rs`, use one `exec` per channel. With a terminal, the bastion ignores the end of the client input, as `sshd` does, since Docker would hang the terminal up. Docker can't stop an `exec`: only removing the container stops its commands.

The CA uses `ssh-key` 0.6, and russh a release candidate of the next version. Keys and certificates cross over between them as OpenSSH text, in the `target.rs` of the bastion.

## Code rules

### Dependencies

The code uses Rust edition 2024 with the stable toolchain, and declares dependency versions once, in `[workspace.dependencies]`. When you add a crate, use its latest released version, as crates.io shows it rather than from memory, and keep dependencies current. Prefer few, well-maintained dependencies.

### Design

Keep authorization logic in `core` and signing in `ca`, so that binaries stay thin. Choose the simplest design that works, and add no abstraction before a second use needs it.

### Security

These rules apply to every change:

- Fail closed: any parsing, verification, or I/O error denies access
- No `unwrap`, `expect`, or `panic!` outside tests and provably infallible cases, justified in a comment
- Never log tokens, private keys, or full certificates: log revocation IDs and key fingerprints
- Only `ca` loads the CA private key: keep its handling isolated and auditable
- Service logs and HTTP errors never quote a token: they carry `Error::kind()` for token errors

Detailed Biscuit errors can quote Datalog written by the token holder, hence the last rule. Certificates are short-lived by default, 120 seconds, because revocation relies on Biscuit revocation IDs, checked at issuance, and on the short lifetime of certificates.

### Documentation

Every public item has a doc comment, which explains what it's for and any non-obvious behavior, such as errors, security implications, or invariants. Each crate describes its role in a crate-level `//!` doc. Comments explain why, not what: add them where they help, such as security reasoning, protocol quirks, or non-obvious choices.

Update the documentation in the same change as the code. The README covers usage and deployment, [docs/certificates.md](https://github.com/davlgd/biscuit-ssh/blob/main/docs/certificates.md) the certificates, and this guide development. Record user-facing changes in [CHANGELOG.md](https://github.com/davlgd/biscuit-ssh/blob/main/CHANGELOG.md), under *Unreleased* until a release.

Write plain, direct English, in the active voice. Keep a sentence under 25 words when possible, and a paragraph to about 80 words. Spell out an acronym at its first use, use the serial comma, and give every code block a language.

Prefer prose to lists, and keep each list item to one line. Write each paragraph on a single line of the source file, and let the editor wrap it: a diff then shows the paragraph that changed.

On GitHub, the repository home shows the README and this guide 838 pixels wide, and the file view other pages 1,012 pixels wide. A list item shouldn't wrap, and the last line of a paragraph shouldn't hold only a few words.

crates.io shows the README files too, where relative links break: use absolute GitHub URLs.

## Check a change

Run these commands before you consider a change done. Clippy must report no warning, and every test must pass:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test --workspace --all-features
```

The runs with `--all-features` check the client with its `certificates` feature, which the other runs leave out.

Test authorization, signing, and the parsing of untrusted input with accepted and rejected cases.

Changes to what reaches `sshd` must also pass [`tests/e2e.sh`](https://github.com/davlgd/biscuit-ssh/blob/main/tests/e2e.sh) against a test deployment, as its header explains. Run it against a dedicated `sshd` instance, never the one you use to administer the test server. Never commit the addresses, host names, or paths of a deployment.

Read your Markdown changes as GitHub renders them, at both widths of [Documentation](https://github.com/davlgd/biscuit-ssh/blob/main/CONTRIBUTING.md#documentation), and test the links.

## Commit messages

Write the subject on one line, as a capitalized imperative sentence, without a prefix or a body:

```text
Add the bastion: token-checked SSH relay with session leases
Harden bastion cuts against stalled targets and failed connections
Send tokens to the bastion in parts, explain refusals and clarify the client
```

## Release

A release commit, `Release 0.3.0`, sets the version of the workspace in `Cargo.toml`, and of the internal crates in `[workspace.dependencies]`. It also updates `Cargo.lock`, and moves the *Unreleased* entries of the changelog under the version and its date. Tag the release commit `v0.3.0`.

Each crate carries its own description, keywords, categories, and README. It also carries the license, through a `LICENSE` link to the one of the repository. Before publishing, `cargo publish --workspace --dry-run` packages every crate, then builds each package against the others, as crates.io would serve them.

`cargo publish --workspace` publishes the crates in dependency order: `biscuit-ssh-core`, `biscuit-ssh-ca`, and `biscuit-ssh-service` first, then the client, the bastion, and the issuer. Publish biscuit-sandbox after them, as it depends on `biscuit-ssh-core` and `biscuit-ssh-service` from crates.io.
