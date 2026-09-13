# biscuit-ssh

SSH access for third parties through [Biscuit](https://www.biscuitsec.org/) tokens.

A token grants logins (`server:account`) and can be restricted by anyone holding it, offline: expiration, source networks, servers, accounts, forced commands, SSH keys. Servers run a stock OpenSSH that only trusts the certificate authority: nothing Biscuit-specific is installed on them. There are two ways in:

- **Certificates**: the holder exchanges the token for a short-lived OpenSSH certificate, and `sshd` enforces the rest.
- **Bastion**: the holder logs in to the bastion with the token, which relays the session to servers only it can reach, and cuts it as soon as the token stops allowing it.

```
holder ── token + SSH public key ──▶ issuer: checks the token for this request
holder ◀──── certificate (120 s) ─── signs with the CA key
holder ── ssh + certificate ───────▶ server: sshd checks CA, principal, source address, validity
```

The certificate carries what was authorized, nothing more:

| Request | Certificate, enforced by `sshd` |
|---|---|
| server and account | single principal `server:account` |
| client address, as seen by the issuer | `source-address` pinned to that address |
| command, if any | `force-command` |
| token validity | `valid-before`, never later than the token allows |

Only `permit-pty` is granted: no agent, port or X11 forwarding.

## Build

```sh
cargo build --release
```

This builds `biscuit-ssh-issuer` and `biscuit-ssh-bastion` (the services) and `biscuit-ssh` (the client and admin tool).

## Deploy

### Keys

```sh
# Biscuit root key: signs tokens. Keep the private key offline.
biscuit-ssh admin keygen -o root.key        # prints the public key, ed25519/...

# SSH certificate authority: signs certificates. Only the issuer reads it.
ssh-keygen -t ed25519 -N "" -C biscuit-ssh-ca -f ca
```

### Issuer

`/etc/biscuit-ssh/issuer.toml`:

```toml
listen = "0.0.0.0:8443"
root_public_key = "ed25519/..."
ca_key = "/etc/biscuit-ssh/ca"                 # mode 600, owned by the service user
revocation_list = "/etc/biscuit-ssh/revoked"   # optional, re-read on each request; create it, even empty

[tls]
certificate = "/etc/biscuit-ssh/tls.crt"
key = "/etc/biscuit-ssh/tls.key"
```

When `revocation_list` is set, the file must exist and be readable by the issuer: until it does, every request is refused (fail closed). Optional settings, with their defaults: `certificate_lifetime = 120` (seconds, at most 600), `clock_skew = 30` (seconds certificates are backdated), `policy` (Datalog verifier policies), `trusted_proxies = []`. Without `[tls]`, the API is served over plain HTTP: only do that behind a TLS-terminating proxy, listed in `trusted_proxies` so the client address is read from the last `X-Forwarded-For` entry (a single proxy is supported, not a chain).

Run it as an unprivileged user, e.g. with systemd:

```ini
[Service]
User=biscuit-ssh
ExecStart=/usr/local/bin/biscuit-ssh-issuer --config /etc/biscuit-ssh/issuer.toml
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
```

Audit events go to stderr (`RUST_LOG` sets verbosity), never with the token itself: each issuance with the client address, server, account, key fingerprint, token identifier and validity; each refusal with the client address, the reason (`denied`, `revoked`, `invalid_token`...) and, once the request is well-formed, server, account and key fingerprint.

### Servers

`sshd_config`:

```
TrustedUserCAKeys /etc/ssh/biscuit-ssh-ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
```

`/etc/ssh/biscuit-ssh-ca.pub` is `ca.pub`, also served by the issuer at `GET /v1/ca`. `/etc/ssh/principals/<account>` lists the principals allowed to log in as that account, one per line, typically `<this server's name>:<account>`, e.g. `web-1:deploy` in `/etc/ssh/principals/deploy` on `web-1`.

Keep server clocks synchronized: a lagging clock extends certificate validity.

### Bastion

`/etc/biscuit-ssh/bastion.toml`:

```toml
listen = "0.0.0.0:2200"
host_key = "/etc/biscuit-ssh/bastion_host_key"   # ssh-keygen -t ed25519 -f bastion_host_key
root_public_key = "ed25519/..."
ca_key = "/etc/biscuit-ssh/ca"
revocation_list = "/etc/biscuit-ssh/revoked"

# Servers reachable through the bastion, by the name tokens use.
[targets.web-1]
address = "10.0.0.5:22"
host_key = "ssh-ed25519 AAAA..."   # the server's host public key, required
```

Optional settings: `session_check_interval = 30` (seconds between token re-evaluations, 5 to 600; a revocation cuts sessions within that time), `clock_skew`, `policy`, and per target `source_address`, the bastion's address as the server sees it when network address translation hides the local one. Run it like the issuer, with its own systemd unit.

Target servers are configured as in [Servers](#servers), the bastion logging in with certificates for the same principals, pinned to its own address: firewall them so that only the bastion reaches their `sshd`.

## Use

The administrator grants access:

```sh
biscuit-ssh admin mint -k root.key -r web-1:deploy -r web-2:deploy --ttl 30d > partner.token
```

The holder can restrict it before using it or handing it over; restrictions add up and can never be removed:

```sh
biscuit-ssh token attenuate -t partner.token --ttl 8h --server web-1 > contractor.token
biscuit-ssh token inspect -t contractor.token    # blocks and revocation identifiers
```

To also pin it to the contractor's network, add e.g. `--source 198.51.100.0/24` with their actual network.

Then connects:

```sh
export BISCUIT_SSH_ISSUER=https://ssh-ca.example.com
biscuit-ssh ssh -t contractor.token --server web-1 deploy@web-1.example.com
```

`ssh` gets a certificate and runs `ssh` with it; what follows the destination goes to `ssh` unchanged, as with `ssh` itself, e.g. `deploy@web-1.example.com -p 2222 uptime`. `--server` is the server name in the token, the destination host by default. `ssh` is kept on the address family the issuer saw, since the certificate only accepts that address. The `ssh` subcommand currently requires a UTF-8 identity path without quotes or backslashes.

Through the bastion, the destination is `account@server`, with the server named as in the token:

```sh
biscuit-ssh ssh --bastion bastion.example.com:2200 -t contractor.token deploy@web-1
```

`biscuit-ssh` runs `ssh` with itself as `SSH_ASKPASS`, answering the bastion's token prompt, and only that one: key passphrases and host key confirmations are still asked on the terminal. Plain `ssh`, `scp` or `sftp` work the same way with `SSH_ASKPASS=biscuit-ssh SSH_ASKPASS_REQUIRE=force BISCUIT_SSH_ASKPASS_TOKEN=<token>`, as long as `BatchMode` is off (it disables keyboard-interactive, hence `sftp -b`). Tokens restricted to commands are refused by the bastion for now.

`login` only gets the certificate, for use with plain `ssh` or other tools within its lifetime:

```sh
biscuit-ssh login web-1 deploy -t contractor.token
ssh deploy@web-1.example.com
```

Both certify `~/.ssh/id_ed25519.pub` (see `--identity`) and write `~/.ssh/id_ed25519-cert.pub`, replacing the previous certificate. Tokens are only ever sent over HTTPS, or plain HTTP to localhost.

When the issuer refuses a token, the client shows the address the issuer saw and, for a denial, a hint: the token's own restrictions that fail when evaluated locally, with the address and time the issuer used and the root public key from `GET /v1/root-key`. The issuer's policies are never disclosed, so this cannot tell everything.

Restriction flags: `--ttl` and `--mode`, plus `--source`, `--server`, `--user`, `--command` (the session is then forced to that command, and `login` must pass it with `--command`) and `--public-key` (fingerprint or `.pub` file), which can be repeated to allow several values.

### Token vocabulary

Tokens can also be written by hand. The issuer describes each request with the facts `time`, `source_ip`, `source_net` (one per network containing the client, from `0.0.0.0/0` to `a.b.c.d/32`), `server`, `user`, `command`, `public_key` and `mode`; the authority block grants `right($server, $user)`. See [`crates/core/src/vocabulary.rs`](crates/core/src/vocabulary.rs) for the full contract.

### Revocation

Add a block's revocation identifier (from `token inspect`, also the certificate key ID logged by `sshd`) to the revocation list: that token and every token derived from it are refused from the next request. Certificates already issued stay valid until they expire (120 s by default).

## Security notes

- A certificate never outlives what its token allows: the token is evaluated at every second of the certificate lifetime, and validity stops at the first refusal.
- `sshd` checks certificates when a session starts: expiration does not close sessions already open. The bastion does: from the second the token stops allowing access (or within `session_check_interval` of a revocation), it relays nothing more, and it closes the client and target connections at most 2 seconds later. Before closing, it sends `HUP` to the remote commands, on a best-effort basis: a stalled target may not receive it, and processes that detach themselves (`nohup`, `setsid`) survive, as with any SSH disconnection.
- The certificate is pinned to the client address the issuer sees, so `sshd` must see the same one: logging in through a jump host, a different NAT or another address family than the one used to reach the issuer is refused.
- The issuer refuses to certify certificates, DSA keys or anything but plain OpenSSH public keys, and fails closed on any error, including an unreadable revocation list.

## Development

See [AGENTS.md](AGENTS.md). End-to-end scenarios against a real deployment: [`tests/e2e.sh`](tests/e2e.sh).

## License

Copyright 2026 davlgd. Licensed under the [Apache License, Version 2.0](LICENSE).
