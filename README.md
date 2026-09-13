# biscuit-ssh

SSH access for third parties through [Biscuit](https://www.biscuitsec.org/) tokens.

An administrator hands out a token that grants logins, such as "account `deploy` on server `web-1`". Whoever holds it can restrict it further, offline and without any key: expiration, source networks, servers, accounts, forced commands, SSH keys. Servers run a stock OpenSSH that only trusts a certificate authority: nothing Biscuit-specific is installed on them. There are two ways in:

- **Certificates**: the holder exchanges the token for a short-lived OpenSSH certificate at the **issuer**, then connects to the server directly; `sshd` enforces the rest.
- **Bastion**: the holder logs in to the **bastion** with the token; it relays the session to servers only it can reach, and cuts it as soon as the token stops allowing it.

```
certificates   holder ── token + SSH public key ─▶ issuer   (checks the token, signs a 120 s certificate)
               holder ── ssh + certificate ──────▶ server   (sshd checks the certificate)

bastion        holder ── ssh + token ────────────▶ bastion  (checks the token, again every 30 s)
                                                     └─────▶ server  (with the bastion's own certificate)
```

## Concepts

- **Token**: a Biscuit, a signed credential made of blocks of rules. The first block, signed with the administrator's **root key**, grants **rights**; each later block, added by any holder, can only add restrictions. Anyone holding a token can use it, so it is a secret.
- **Server name**: a label the administrator chooses for each server, e.g. `web-1`. It appears in token rights, in the server's principals file, and in the bastion configuration. It is not a DNS name or an address, although the two often coincide.
- **Account**: the Unix account on the server, e.g. `deploy`.
- **Principal**: `server:account`, e.g. `web-1:deploy`. Certificates carry exactly one; each server lists, per account, the principals it accepts.
- **Attenuation**: adding restrictions to a token (`biscuit-ssh token attenuate`). The result can never grant more than the original.
- **Revocation identifier**: each block of a token has one. Revoking a block refuses every token that contains it: the token ending with that block, and all tokens later derived from it. The last block therefore identifies one exact token, the first one the whole family.

## Quick start

With a deployment already running (see [Administration](#administration)), an administrator holding the root key can try both ways in:

```sh
ssh-keygen -t ed25519 -N "" -f ./id_test                       # a key for the test
biscuit-ssh admin mint -k root.key -r web-1:deploy --ttl 1h > my.token

# certificate from the issuer, then direct connection
biscuit-ssh ssh --issuer https://ssh-ca.example.com -t my.token -i ./id_test --server web-1 deploy@web-1.example.com

# through the bastion
biscuit-ssh ssh --bastion bastion.example.com:2200 -t my.token -i ./id_test deploy@web-1
```

## For token holders

You receive a token file and, depending on the mode:

- certificates: the issuer URL, and its CA certificate if the issuer uses a private one;
- bastion: its address and the fingerprint of its host key.

You need the `biscuit-ssh` client (built from source for now, see [Build](#build)), the OpenSSH client, and an SSH key: the certificate is issued for it, and the bastion requires one too. The default is `~/.ssh/id_ed25519`; choose another one with `-i` (and create one with `ssh-keygen -t ed25519` if needed).

### With certificates

```sh
export BISCUIT_SSH_ISSUER=https://ssh-ca.example.com
biscuit-ssh ssh -t my.token --server web-1 deploy@web-1.example.com
```

`biscuit-ssh ssh` gets a certificate for the server named `web-1` in the token, then runs `ssh` with it. What follows the destination goes to `ssh` unchanged, e.g. `deploy@web-1.example.com -p 2222 uptime`. Without `--server`, the server name is the destination host, which suits deployments where server names are host names; connecting by address, e.g. `deploy@192.0.2.10`, always needs it.

With a private issuer CA, add `--issuer-ca ca.crt` or set `BISCUIT_SSH_ISSUER_CA`. `biscuit-ssh login web-1 deploy -t my.token` only gets the certificate, for plain `ssh`, `scp` or other tools during its lifetime. Both write the certificate next to the key (`~/.ssh/id_ed25519-cert.pub` by default), replacing the previous one; `ssh` finds it there by itself.

The certificate only accepts the address the issuer saw, so that a stolen certificate is useless elsewhere: `ssh` must leave from the same address (no jump host, no different NAT or VPN), and `biscuit-ssh ssh` keeps it on the same address family.

### Through the bastion

```sh
biscuit-ssh ssh --bastion bastion.example.com:2200 -t my.token deploy@web-1
```

The destination is `account@server`, with the server named as in the token. On first connection, `ssh` shows the bastion's host key fingerprint: compare it with the one you received. `biscuit-ssh` runs `ssh` with itself as `SSH_ASKPASS` to answer the bastion's token prompts, and only those: key passphrases and host key confirmations are still asked on the terminal. Plain `ssh`, `scp` or `sftp` work the same way, with the login `account@server`:

```sh
env SSH_ASKPASS=biscuit-ssh SSH_ASKPASS_REQUIRE=force BISCUIT_SSH_ASKPASS_TOKEN="$(cat my.token)" \
  sftp -P 2200 -o User=deploy@web-1 bastion.example.com
```

`BISCUIT_SSH_ASKPASS_TOKEN` holds the token itself, not a file name. `BatchMode` must stay off (it disables the token prompt; `sftp -b` turns it on). Tokens restricted to commands are refused by the bastion for now.

### Host keys

As with any SSH server, check a host key before trusting it. `ssh` records it in `~/.ssh/known_hosts` unless told otherwise. To check a fingerprint you received without connecting:

```sh
ssh-keyscan -p 2200 bastion.example.com > known_hosts
ssh-keygen -lf known_hosts        # compare with the fingerprint you received
```

That `known_hosts` file can then be passed with `-o UserKnownHostsFile=known_hosts`.

### From scripts and agents

Nothing may wait for a terminal:

- always pass the token with `-t FILE` (or `BISCUIT_SSH_TOKEN_FILE`); `-t -` reads it from standard input;
- trust host keys beforehand, with a checked `known_hosts` file as above, or `-o StrictHostKeyChecking=accept-new` to trust whatever key is seen first;
- bound connection time with `-o ConnectTimeout=15`, and give `ssh` no input with `</dev/null` when there is none.

```sh
biscuit-ssh ssh --bastion bastion.example.com:2200 -t my.token -i ./id_ed25519 deploy@web-1 \
  -o UserKnownHostsFile=./known_hosts -o ConnectTimeout=15 uptime </dev/null
```

Options before the destination are `biscuit-ssh`'s, those after it `ssh`'s (after it, `-t` is `ssh`'s request for a terminal).

### Handing access over

Restrict your token before passing it on; restrictions add up:

```sh
biscuit-ssh token attenuate -t my.token --ttl 8h --server web-1 --source 198.51.100.0/24 > contractor.token
biscuit-ssh token inspect -t contractor.token
```

Restriction flags: `--ttl` (from now, e.g. `90s`, `15m`, `8h`, `30d`), `--mode certificate|bastion` (one way in only; `bastion` for access that is cut as soon as it ends), and the repeatable `--source` (network or address), `--server`, `--user`, `--command` (the session is forced to that command, and `login`/`ssh` must pass it with `--command`) and `--public-key` (fingerprint or `.pub` file of the only key allowed). `inspect` shows the blocks with their revocation identifiers, and times in UTC.

Send the recipient, over a secure channel: the token file, how to connect (issuer URL and CA, or bastion address and host key fingerprint), the account and server name, and when it expires. Keep the last block's revocation identifier: it is what to revoke to cut exactly that token.

### Troubleshooting

| Message | Meaning |
|---|---|
| `the issuer refused (403 Forbidden): denied` | The token does not allow this request. The hint below it lists the failing restrictions, or the rights the token grants when the server or account does not match (use `--server`). |
| `cannot reach … (if the issuer uses a private CA, pass it with --issuer-ca)` | The issuer's TLS certificate is signed by a CA the client does not trust. |
| `cannot reach …`, `Connection timed out` (e.g. `during banner exchange`), `Connection reset by peer` | Network: wrong address or port, a firewall, or the service is down. `curl https://<issuer>/v1/ca` (with `--cacert` for a private CA) checks the issuer, `ssh-keyscan -p <port> <bastion>` the bastion. |
| `biscuit-ssh bastion: access refused (denied) …` | The token does not allow this login: unknown server, other account, a failing restriction, or expired. |
| `access refused (invalid_login)` | The bastion login must be `account@server`. |
| `access refused (revoked)` / `(invalid_token)` | The token was revoked, or was not issued for this deployment. |
| `Permission denied (publickey,keyboard-interactive)` from the bastion | No SSH key was offered: the bastion needs one before the token. |
| `no terminal to answer ssh's question` | `ssh` asked something (host key confirmation, key passphrase) with no terminal: see [From scripts and agents](#from-scripts-and-agents). |
| `Permission denied` from a server with a fresh certificate | Wrong address (see the certificate's `source-address` with `ssh-keygen -L -f <key>-cert.pub`), or the server does not list this principal. |

## Administration

### Build

```sh
cargo build --release
sudo install target/release/biscuit-ssh /usr/local/bin/                     # client and admin tool
sudo install target/release/biscuit-ssh-issuer target/release/biscuit-ssh-bastion /usr/local/bin/  # services
```

This needs a stable Rust toolchain. Services run on Linux; the client also runs on macOS.

### Keys and service account

On the administration machine, the root key:

```sh
biscuit-ssh admin keygen -o root.key        # prints the public key, ed25519/..., for the services
```

On the machines running the services, an unprivileged account and the certificate authority. Generate the CA once, on one of them; the issuer and the bastion must use the same one, so copy `ca` to the other with the same ownership and mode:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin biscuit-ssh
sudo install -d -m 755 /etc/biscuit-ssh
sudo ssh-keygen -t ed25519 -N "" -C biscuit-ssh-ca -f /etc/biscuit-ssh/ca
sudo chown biscuit-ssh: /etc/biscuit-ssh/ca && sudo chmod 600 /etc/biscuit-ssh/ca
sudo touch /etc/biscuit-ssh/revoked         # the revocation list, empty for now
```

Anyone holding the root key can grant any access; anyone holding the CA key can log in anywhere. If one leaks, replace it (and `root_public_key`, or the servers' `TrustedUserCAKeys`): every token or certificate it signed becomes invalid.

### Granting access

```sh
biscuit-ssh admin mint -k root.key -r web-1:deploy -r web-2:deploy --ttl 30d > partner.token
biscuit-ssh admin mint -k root.key -r web-1:deploy --mode bastion --ttl 8h > contractor.token
```

`-r server:account` grants a right, and the restriction flags above apply; without `--ttl`, the token never expires. Administrators mint one token per recipient, holders attenuate theirs to pass it on: revoking a minted token's first block then affects nobody else, whereas revoking the first block of a token attenuated for several people revokes them all.

### Servers

`sshd_config`:

```
TrustedUserCAKeys /etc/ssh/biscuit-ssh-ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
```

`/etc/ssh/biscuit-ssh-ca.pub` is `ca.pub`, also served by the issuer at `GET /v1/ca`. `/etc/ssh/principals/<account>` lists the principals allowed to log in as that account, one per line, typically `<this server's name>:<account>`: `web-1:deploy` in `/etc/ssh/principals/deploy` on `web-1`. Keep server clocks synchronized: a lagging clock extends certificate validity. Servers behind the bastion get the same configuration, and a firewall letting only the bastion reach their `sshd`.

### Issuer

`/etc/biscuit-ssh/issuer.toml`:

```toml
listen = "0.0.0.0:8443"
root_public_key = "ed25519/..."
ca_key = "/etc/biscuit-ssh/ca"
revocation_list = "/etc/biscuit-ssh/revoked"

[tls]
certificate = "/etc/biscuit-ssh/tls.crt"   # your certificate chain and key, in PEM,
key = "/etc/biscuit-ssh/tls.key"           # readable by the biscuit-ssh account
```

Optional settings, with their defaults: `certificate_lifetime = 120` (seconds, at most 600), `clock_skew = 30` (seconds certificates are backdated), `policy` (Datalog verifier policies), `trusted_proxies = []`. Without `[tls]`, the API is served over plain HTTP: the client only sends tokens over HTTPS or to localhost, so do that behind a TLS-terminating proxy only, listed in `trusted_proxies` so the client address is read from the last `X-Forwarded-For` entry (a single proxy, not a chain).

Run `biscuit-ssh-issuer --config /etc/biscuit-ssh/issuer.toml` as the `biscuit-ssh` account, e.g. with systemd:

```ini
[Service]
User=biscuit-ssh
ExecStart=/usr/local/bin/biscuit-ssh-issuer --config /etc/biscuit-ssh/issuer.toml
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
```

### Bastion

```sh
sudo ssh-keygen -t ed25519 -N "" -C biscuit-ssh-bastion -f /etc/biscuit-ssh/bastion_host_key
sudo chown biscuit-ssh: /etc/biscuit-ssh/bastion_host_key
```

`/etc/biscuit-ssh/bastion.toml`:

```toml
listen = "0.0.0.0:2200"
host_key = "/etc/biscuit-ssh/bastion_host_key"
root_public_key = "ed25519/..."
ca_key = "/etc/biscuit-ssh/ca"
revocation_list = "/etc/biscuit-ssh/revoked"

# Servers reachable through the bastion, by server name.
[targets.web-1]
address = "10.0.0.5:22"
host_key = "ssh-ed25519 AAAA..."   # that server's host public key: any other is refused
```

Optional settings: `session_check_interval = 30` (seconds between token re-evaluations, 5 to 600), `clock_skew`, `policy`, and per target `source_address`, the bastion's address as the server sees it when network address translation hides the local one (the bastion's certificates are pinned to it). Run `biscuit-ssh-bastion --config /etc/biscuit-ssh/bastion.toml` like the issuer, with its own unit. It logs its host key fingerprint at startup: give it to token holders.

### Revocation

The revocation list is a text file with one revocation identifier per line (hex, from `biscuit-ssh token inspect`, or the key ID `sshd` logs for a certificate, which is the token's last block); blank lines and lines starting with `#` are ignored. Revoking needs `revocation_list` to be set beforehand; the issuer and the bastion can share one file. Each re-reads it on every check, and refuses everything while it is unreadable. Once an identifier is added:

- the issuer refuses the tokens containing that block on the next request; certificates already issued stay valid until they expire (120 s by default), and sessions already open are not closed;
- the bastion refuses new logins, and cuts open sessions at its next check, within `session_check_interval`.

### Logs

Both services log to stderr (`RUST_LOG` sets verbosity), never the token itself:

- issuer: each certificate issued, with the client address, server, account, key fingerprint, token identifier and validity; each refusal with the client address, the reason, and, when the request is well-formed, server, account and key fingerprint;
- bastion: each login with the client address, server, account, key fingerprint and token identifier; each refusal with the client address and reason; commands and subsystems run; sessions cut and why.

## Token rules

Tokens can also be written by hand in Datalog. For each request, the services provide facts: `time`, `source_ip`, `source_net` (one per network containing the client, from `0.0.0.0/0` to `a.b.c.d/32`), `server`, `user`, `command`, `public_key` (fingerprint of the key the holder authenticates with) and `mode` (`certificate` or `bastion`). A token grants `right($server, $user)` in its first block, and restricts with checks such as `check if server($s), ["web-1"].contains($s)`: with the default policy, a request is allowed when every check passes and a right of the first block matches. [`crates/core/src/vocabulary.rs`](crates/core/src/vocabulary.rs) documents the full contract.

## Security notes

- A certificate never outlives what its token allows: the token is evaluated at every second of the certificate lifetime, and validity stops at the first refusal.
- `sshd` checks certificates when a session starts: expiration does not close sessions already open. The bastion does: from the second the token stops allowing access (or within `session_check_interval` of a revocation), it relays nothing more, and it closes the client and server connections at most 2 seconds later. Before closing, it sends `HUP` to the remote commands, on a best-effort basis: a stalled server may not receive it, and processes that detach themselves (`nohup`, `setsid`) survive, as with any SSH disconnection.
- The client sends tokens to the issuer over HTTPS only (plain HTTP to localhost excepted); the bastion receives them inside SSH.
- The issuer refuses to certify certificates, DSA keys or anything but plain OpenSSH public keys. Both services fail closed on any error, including an unreadable revocation list.

## Development

See [AGENTS.md](AGENTS.md). End-to-end scenarios against a real deployment: [`tests/e2e.sh`](tests/e2e.sh).

## License

Copyright 2026 davlgd. Licensed under the [Apache License, Version 2.0](LICENSE).
