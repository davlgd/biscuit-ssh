# Certificates

Token holders can also exchange their token for a short-lived OpenSSH certificate at the issuer, instead of logging in through the bastion. They then connect to servers directly, and `sshd` enforces the restrictions. The [README](https://github.com/davlgd/biscuit-ssh/blob/main/README.md) covers tokens, keys, servers, and revocation.

```text
holder ── token + SSH public key ─▶ issuer  (checks the token, signs a 120 s certificate)
holder ── ssh + certificate ──────▶ server  (sshd checks the certificate)
```

## Choose a way in

Certificates suit servers that token holders can already reach. Nothing runs between the holder and the server, so no intermediary sees the session. Once issued, a certificate works with plain `ssh`, `scp`, `rsync`, or any other SSH tool, without prompts.

Their guarantees are weaker than those of the bastion. `sshd` only checks a certificate when a session starts, so sessions stay open after the token expires, or after you revoke it. A certificate issued before a revocation stays valid until it expires, 120 seconds later by default. It also only accepts the address the issuer saw, which network changes can break.

Restrict a token to one way in with `--mode certificate` or `--mode bastion`, when you attenuate or mint it.

## Connect with a certificate

With your token file, you receive the issuer URL, and its CA certificate if the issuer uses a private one. You also need the OpenSSH client, the SSH key the issuer certifies, and a `biscuit-ssh` client built with certificates, as [Build](https://github.com/davlgd/biscuit-ssh/blob/main/docs/certificates.md#build) explains.

```bash
export BISCUIT_SSH_ISSUER=https://ssh-ca.example.com
biscuit-ssh ssh -t my.token --server web-1 deploy@web-1.example.com
```

`biscuit-ssh ssh` gets a certificate for the server named `web-1` in the token, then runs `ssh` with it. Arguments after the destination go to `ssh` unchanged, such as `deploy@web-1.example.com -p 2222 uptime`. Without `--server`, the server name is the destination host. This suits server names that are host names, but connecting by address, such as `deploy@192.0.2.10`, always needs `--server`.

With a private issuer CA, add `--issuer-ca ca.crt`, or set `BISCUIT_SSH_ISSUER_CA`. To get the certificate only, run `biscuit-ssh login web-1 deploy -t my.token`, then use plain `ssh`, `scp`, or other tools during its lifetime. Both commands write the certificate next to the key, such as `~/.ssh/id_ed25519-cert.pub`, where `ssh` finds it, and replace the previous one.

The certificate only accepts the address the issuer saw, so a stolen certificate is useless elsewhere. Your `ssh` connection must leave from this address: no jump host, and no other network address translation (NAT) or VPN. `biscuit-ssh ssh` keeps it on the same address family.

### Force a command

`--command` restricts a token to sessions forced to a command, such as for a backup job. Pass the same command to `biscuit-ssh ssh` or `biscuit-ssh login`, before the destination:

```bash
biscuit-ssh token attenuate -t my.token --command uptime > uptime.token
biscuit-ssh ssh -t uptime.token --command uptime --server web-1 deploy@web-1.example.com
```

The certificate then carries `force-command`, and `sshd` runs this command whatever the client asks. To allow several commands, repeat `--command` when you restrict the token. A token restricted to commands refuses interactive sessions. `biscuit-ssh ssh` logs in afresh, rather than joining a multiplexed connection, and with a forced command refuses the multiplexing options of `ssh`. The bastion can force commands too, as the [README](https://github.com/davlgd/biscuit-ssh/blob/main/README.md#force-a-command) explains.

### Troubleshooting

| Message                                                           | Meaning                                                                    |
| ----------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `the issuer refused (400 Bad Request): …`                         | A malformed request: the message tells which field                         |
| `the issuer refused (500 Internal Server Error): internal error`  | The issuer failed, such as on an unreadable revocation list                |
| `the issuer refused (503 Service Unavailable): busy, retry later` | Too many requests at once, or token checks too slow                        |
| `cannot reach … (if the issuer uses a private CA, …)`             | A CA the client doesn't trust signed the TLS certificate of the issuer     |
| `cannot reach …`                                                  | Network: wrong address or port, a firewall, or the issuer is down          |
| `Permission denied`, from a server, with a fresh certificate      | Wrong address, or the server doesn't list this principal                   |
| `the issuer refused (403 Forbidden): denied`                      | The token doesn't allow this request: the hint below the message tells why |

`curl https://<issuer>/v1/ca` checks that the issuer answers, with `--cacert` for a private CA. When a server refuses a fresh certificate, `ssh-keygen -L -f <key>-cert.pub` shows the address the certificate accepts, in `source-address`.

When the issuer refuses a token, the hint lists the failing restrictions. If the server or account doesn't match, it lists the rights of the token instead: pass the right server with `--server`.

## Run the issuer

### Build

Certificates are off by default: a plain `cargo build` leaves the issuer out, and builds a client that only connects through the bastion. Build the issuer, and a client with the `certificates` feature:

```bash
cargo build --release -p biscuit-ssh-issuer -p biscuit-ssh --features certificates
sudo install target/release/biscuit-ssh-issuer target/release/biscuit-ssh /usr/local/bin/
```

Install this client for the token holders who connect with certificates. It also connects through the bastion, as the default client does.

### Configure it

The issuer signs certificates with the CA of the bastion, which servers already trust, as [Create the keys](https://github.com/davlgd/biscuit-ssh/blob/main/README.md#create-the-keys) explains. On a machine of its own, copy `/etc/biscuit-ssh/ca` with the same owner and mode. The issuer also serves the public key of the CA at `GET /v1/ca`.

Write `/etc/biscuit-ssh/issuer.toml`, with your TLS certificate chain and key. Give them in Privacy-Enhanced Mail (PEM) format, and make them readable by the `biscuit-ssh` account, which runs the issuer:

```toml
listen = "0.0.0.0:8443"
root_public_key = "ed25519/..."
ca_key = "/etc/biscuit-ssh/ca"
revocation_list = "/etc/biscuit-ssh/revoked"

[tls]
certificate = "/etc/biscuit-ssh/tls.crt"
key = "/etc/biscuit-ssh/tls.key"
```

| Optional setting       | Default                                         | Meaning                                                            |
| ---------------------- | ----------------------------------------------- | ------------------------------------------------------------------ |
| `certificate_lifetime` | `120`                                           | Lifetime of certificates, at most 600 seconds                      |
| `clock_skew`           | `30`                                            | How far back certificates start, at most 300 s                     |
| `policy`               | `allow if server($s), user($u), right($s, $u);` | Datalog policies of the verifier                                   |
| `revocation_list`      | None                                            | The revocation list: without it, the issuer never revokes anything |
| `trusted_proxies`      | `[]`                                            | Proxies trusted to report the client address                       |

Without `[tls]`, the issuer serves its API over plain HTTP. The client only sends tokens over HTTPS, or plain HTTP to `localhost`, `127.0.0.1`, or `[::1]`, so serve plain HTTP only behind a TLS-terminating proxy. List this proxy in `trusted_proxies`: the issuer then reads the client address from the last `X-Forwarded-For` entry, which supports one proxy, not a chain.

Check the configuration with `biscuit-ssh-issuer --check --config /etc/biscuit-ssh/issuer.toml`, as the `biscuit-ssh` account. It loads the keys, the revocation list, and the TLS certificate, then exits without listening. Run `biscuit-ssh-issuer --config /etc/biscuit-ssh/issuer.toml` as this account, for example with this systemd unit:

```ini
[Service]
User=biscuit-ssh
ExecStart=/usr/local/bin/biscuit-ssh-issuer --config /etc/biscuit-ssh/issuer.toml
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
```

### Revoke access

The issuer and the bastion can share one [revocation list](https://github.com/davlgd/biscuit-ssh/blob/main/README.md#revoke-access). The issuer reads it again at every request, and refuses everything while it's unreadable. Once you add an identifier:

- The issuer refuses the matching tokens from the next request
- Certificates already issued stay valid until they expire, after 120 seconds by default
- Sessions already open with a certificate stay open

The key ID of a certificate, which `sshd` logs, is the revocation identifier of the last block of its token.

### Read the logs

The issuer logs to stderr, with the verbosity `RUST_LOG` sets, and never logs tokens.

It logs each certificate it issues, with the client address, server, account, key fingerprint, token identifier, and validity. It logs each refusal with the client address and the reason, plus the server, account, and key fingerprint when the request is well-formed.

## Security

A certificate never outlives what its token allows. The issuer evaluates the token at every second of the certificate lifetime, and stops at the first refusal. The lifetime itself never exceeds `certificate_lifetime`, 120 seconds by default.

A certificate only permits a terminal: `sshd` refuses port, agent, and X11 forwarding, and skips `~/.ssh/rc`.

The client only sends tokens to the issuer over HTTPS, or plain HTTP to `localhost`, `127.0.0.1`, or `[::1]`. It refuses issuer URLs with credentials, a query, or a fragment. The issuer refuses to certify certificates, Digital Signature Algorithm (DSA) keys, and anything but plain OpenSSH public keys. It fails closed on any error, such as an unreadable revocation list: it refuses access.
