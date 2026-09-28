# Changelog

## Unreleased

- Bastion: sessions in Docker containers (`[containers]`), through `docker exec`, with their own root key and revocation list; a token signed by one root key never reaches the other kind of target.
- Bastion: terminal sessions in containers stay open when the client closes its input, as with sshd.
- New `sandbox/` application: a REST service creating disposable containers from Docker Hub images, reachable only through the bastion with a token restricted to the requesting address, and removed when the token expires or is revoked.
- Services: revocation reading and TLS serving shared by the issuer, the bastion and the sandbox.

## 0.2.0

- Bastion: token-checked SSH relay to servers only it can reach, cutting sessions when the token expires or is revoked.
- Client: `biscuit-ssh ssh`, direct with a certificate or `--bastion`; explanations of refusals.

## 0.1.0

- Initial release: Biscuit tokens exchanged for short-lived OpenSSH certificates at the issuer, and the `biscuit-ssh` client.
