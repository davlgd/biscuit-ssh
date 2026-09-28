# biscuit-ssh-sandbox

Disposable containers reachable by SSH, only through the [biscuit-ssh](../README.md) bastion.

A client asks the REST API for a container running a Docker Hub image. The service starts it and answers with a Biscuit token valid for one hour, and only from the client's address. With that token, the client opens SSH sessions in the container through the bastion. When the token expires or is revoked, the container is removed.

```
client ── POST /v1/sandboxes {"image": "alpine"} ─▶ sandbox  (pulls, starts, mints a token)
client ── ssh + token ───────────────────────────▶ bastion  (checks the token)
                                                     └──────▶ container (docker exec)
```

Unreleased: this relies on the bastion's container support, to be released with biscuit-ssh 0.3.0.

## Using it

Requests only succeed from allowed addresses; any other one gets `401 {"error": "authentication failed"}`, whatever the request. Responses are JSON, errors `{"error": "..."}`.

```sh
# Create: 201, with the token and how to connect.
curl -s https://sandbox.example.com:8444/v1/sandboxes -d '{"image": "alpine:3.20"}' -H 'content-type: application/json'
```

```json
{
  "name": "sb-6f1c…",
  "image": "docker.io/library/alpine:3.20",
  "image_id": "sha256:…",
  "expires_at": 1790000000,
  "client_ip": "203.0.113.7",
  "login": "root@sb-6f1c…",
  "bastion": "bastion.example.com:2200",
  "bastion_host_key": "SHA256:…",
  "token": "En0K…",
  "command": "biscuit-ssh ssh --bastion bastion.example.com:2200 -t sandbox.token root@sb-6f1c… -4"
}
```

Save `token` to `sandbox.token`, then run `command` (with the [biscuit-ssh client](../README.md#for-token-holders)); check the bastion's host key against `bastion_host_key` on first connection. Connect from `client_ip`: the token accepts no other address.

| Request | Answer |
|---|---|
| `POST /v1/sandboxes` `{"image": "...", "ttl": 3600}` | `201` as above. `ttl` (seconds, 60 to the configured lifetime, one hour by default) is optional. |
| `POST /v1/sandboxes/{name}/renew` `{"ttl": 3600}` (body optional) | `200`, a new token for the client, valid `ttl` from now; the previous token is revoked. The sandbox's life can only grow (`409` otherwise). |
| `DELETE /v1/sandboxes/{name}` | `204`: the token is revoked, the container removed, open sessions end. |
| `GET /v1/sandboxes` | `200`, the sandboxes with their status and expiry, never their tokens. |

Errors: `400` malformed request, image reference or `ttl`; `404` unknown sandbox, or image not found on Docker Hub; `409` conflicting state; `422` image not usable (see below); `429` too many sandboxes or creations; `502` Docker Hub failed; `503` Docker failed (retried).

Images come from Docker Hub only (`alpine`, `alpine:3.20`, `bitnami/redis`, with an optional `@sha256:` digest). They must be Linux images providing `/bin/sh`, whose command keeps running (the container runs like `docker run -dit`, so images whose command is a shell do); others are refused with `422`. Sessions run as `root`, in `bash` if present, `sh` otherwise; there is no `sftp`.

## What a sandbox is allowed

- No network at all: sessions go through the Docker API, not the network.
- Bounded memory (without swap), CPU and processes, logs capped at 1 MB, no privilege escalation (`no-new-privileges`).
- One hour at most; removed within 10 seconds of its token's expiry or revocation, while the service runs. After a restart, the service first finishes what it left: interrupted creations are undone, pending deletions completed, and containers of its own it does not know removed. It never touches other containers.

Not bounded by default: the disk used by images and by writes inside containers. Give Docker a filesystem of its own (its `data-root`) so a sandbox cannot fill the host's, and, where Docker's storage supports it (overlay2 on XFS with project quotas), set `limits.disk_mb` to cap each container's writes.

## Running it

The service needs the Docker socket (equivalent to root on the host), a signing key of its own, and a bastion configured with the matching `[containers]` section.

```sh
cd sandbox && cargo build --release
sudo install target/release/biscuit-ssh-sandbox /usr/local/bin/

# Signing key: its public key goes to the bastion's [containers] root_public_key.
sudo biscuit-ssh admin keygen -o /etc/biscuit-ssh/sandbox.key
sudo chown biscuit-ssh: /etc/biscuit-ssh/sandbox.key && sudo chmod 600 /etc/biscuit-ssh/sandbox.key
sudo install -d -o biscuit-ssh -g biscuit-ssh /var/lib/biscuit-ssh-sandbox
```

`/etc/biscuit-ssh/sandbox.toml`:

```toml
listen = "0.0.0.0:8444"
allowed_clients = ["203.0.113.7"]
signing_key = "/etc/biscuit-ssh/sandbox.key"
state_dir = "/var/lib/biscuit-ssh-sandbox"
revocation_list = "/var/lib/biscuit-ssh-sandbox/revoked"   # the bastion's [containers] revocation_list

[bastion]
address = "bastion.example.com:2200"
host_key = "SHA256:..."   # logged by the bastion at startup

[tls]
certificate = "/etc/biscuit-ssh/tls.crt"
key = "/etc/biscuit-ssh/tls.key"
```

Optional settings, with their defaults: `label = "biscuit-ssh.sandbox"` (the bastion's `[containers] label`), `account = "root"`, `socket = "/var/run/docker.sock"`, and under `[limits]`: `lifetime = 3600`, `max_sandboxes = 5`, `max_creations = 2`, `memory_mb = 512`, `cpus = 1.0`, `pids = 256`, `pull_timeout = 300`, and `disk_mb` (unset: see above).

The bastion side (see [Containers](../README.md#containers-unreleased)):

```toml
[containers]
root_public_key = "ed25519/..."   # printed by `admin keygen` above
revocation_list = "/var/lib/biscuit-ssh-sandbox/revoked"
label = "biscuit-ssh.sandbox"
```

Run it with systemd, one instance per state directory:

```ini
[Service]
User=biscuit-ssh
SupplementaryGroups=docker
ExecStart=/usr/local/bin/biscuit-ssh-sandbox --config /etc/biscuit-ssh/sandbox.toml
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/biscuit-ssh-sandbox
```

The bastion also needs `SupplementaryGroups=docker`.

## Security model

- Clients are identified by address only, and share every sandbox: any allowed client can renew or delete any of them. An address is not a person; put the service behind a network you control.
- The sandbox signs tokens with a key that only reaches containers: a leaked sandbox key does not give access to the bastion's servers. The service and the bastion still hold Docker access, which a compromise of either turns into root on the host.
- The revocation list is the service's own: revoke a sandbox with `DELETE`, not by editing the file.
- Commands running in a container stop when the container is removed, not when a session is cut: a renewal revokes the previous token without stopping what it started.

## Development

Separate Cargo workspace; see [AGENTS.md](../AGENTS.md). End-to-end scenarios against a running service and bastion: [`tests/e2e.sh`](tests/e2e.sh).
