# Changelog

User-facing changes of biscuit-ssh, the most recent first.

## 0.3.0 - 2026-11-10

- Bastion: forced commands, asked for when the token alone doesn't allow a login, checked with the token
- Client: `ssh --command` through the bastion too, which restricts the token to this command first
- Client: `ssh` logs in afresh unless told to multiplex, and refuses multiplexing options with a forced command
- Client: `token inspect --json`, for scripts
- Bastion, issuer: `--check` validates the configuration, keys, revocation lists, and TLS certificate, then exits
- Bastion: sessions in Docker containers through `docker exec`, enabled by a `[containers]` section
- Bastion: containers have a root key of their own, distinct from the main one, and their own revocation list
- Bastion: terminal sessions in containers stay open when the client closes its input, as with `sshd`
- Build: certificates are off by default; build the issuer, and the client with its `certificates` feature, on request
- Client: `BISCUIT_SSH_TOKEN` holds the token itself, for agents and CI jobs; an explicit `-i` must exist
- Bastion: retries a token check that times out while the lease lasts, and refuses it as `busy` at login
- Bastion: refuses RSA host keys, since the RSA implementation is open to timing attacks
- Issuer: a token check that times out answers `503 busy` instead of `403 denied`
- Dependencies: updated, including rustls 0.23.46 and its security fixes, and russh 0.65

## 0.2.0 - 2026-09-13

- Bastion: SSH relay to servers only it can reach, which cuts sessions when their token expires or when you revoke it
- Client: `biscuit-ssh ssh`, direct with a certificate or through `--bastion`, with explanations of refusals

## 0.1.0 - 2026-09-12

- Initial release: the issuer exchanges Biscuit tokens for short-lived OpenSSH certificates
- Client: `biscuit-ssh`, to get certificates, restrict and inspect tokens, and administer root keys
