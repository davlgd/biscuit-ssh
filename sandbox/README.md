# biscuit-ssh-sandbox

Disposable containers reachable by SSH, only through the [biscuit-ssh](../README.md) bastion.

A client asks the REST API for a container running a Docker Hub image. The service starts it and answers with a token (a [Biscuit](../README.md#concepts): a signed credential the bastion checks) valid for one hour, and only from the client's address. With that token, the client opens SSH sessions in the container through the bastion. When the token expires or is revoked, the container is removed.

```
client ── POST /v1/sandboxes {"image": "alpine"} ─▶ sandbox  (pulls, starts, mints a token)
client ── ssh + token ───────────────────────────▶ bastion  (checks the token)
                                                     └──────▶ container (docker exec)
```

Unreleased: this relies on the bastion's container support, to be released with biscuit-ssh 0.3.0. The [biscuit-ssh client](../README.md#for-token-holders) of any version connects.

## Quick start

You need `curl`, `jq`, the `biscuit-ssh` client, and an SSH key (any key: the bastion requires one, it does not identify you). Add `--cacert ca.crt` to `curl` if the service uses a certificate from a private authority.

```sh
API=https://sandbox.example.com:8444/v1/sandboxes
ssh-keygen -q -t ed25519 -N '' -f sandbox_key                     # once

# Create: may take minutes while the image is pulled, keep curl's timeout long.
curl -sS "$API" -d '{"image": "python:3.13-slim"}' > sandbox.json
NAME=$(jq -r .name sandbox.json)
jq -r .token sandbox.json > "$NAME.token"
jq -r .bastion_known_hosts sandbox.json > known_hosts          # trusts the bastion, no prompt

# Run commands (or nothing, for a shell), as many times as needed.
$(jq -r .command sandbox.json) -i sandbox_key -o UserKnownHostsFile=known_hosts 'python3 --version'

# Done: remove it now rather than at expiry.
curl -sS -X DELETE "$API/$NAME"
```

`command` is `biscuit-ssh ssh --bastion <bastion> -t <name>.token root@<name> -4`: the token only accepts the address it was requested from (`client_ip`), so `-4` (or `-6`) keeps the connection on that address's family. Without `-i`, the client uses your default SSH key. The main README covers [scripts and agents](../README.md#from-scripts-and-agents) (no terminal, no prompts) and [troubleshooting](../README.md#troubleshooting) connections.

## What a sandbox is

- **A Linux container of the image, running as `root`**, with `bash` if the image has it, `sh` otherwise. There is no `sftp`: copy files through a session (`cat file | … 'cat > file'`).
- **No network but loopback.** Package managers (`apk`, `apt`, `pip`) fail, with DNS errors: use an image that already has your tools.
- **Bounded**: memory (without swap), CPU and processes, as configured, logs capped at 1 MB. Commands run with no privilege escalation (`no-new-privileges`) and only the capabilities `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `FSETID`, `KILL`, `SETGID` and `SETUID`: files and processes of its own, no raw sockets, devices, mounts or `chroot`.
- **Its life is its token's.** A token lasts `ttl` seconds (60 to one hour, one hour by default) from its creation or renewal. When it expires, or on `DELETE`, the container is removed with everything in it; the service checks every 10 seconds, and retries while Docker fails.
- **Renewing** gives a new token valid `ttl` from now, never shortening the sandbox's life: renewing before each expiry keeps a sandbox indefinitely. The previous token is revoked at once: sessions opened with it are cut by the bastion at its next check (30 seconds by default), and new ones need the new token. Commands already started keep running; only removing the container stops them.
- **Shared by allowed addresses**: any client allowed to use the API can list, renew and delete every sandbox. Keep the `name` of yours.

## API

Requests only succeed from allowed addresses; any other one gets `401 {"error": "authentication failed"}`, whatever the request. Bodies are JSON (the content type is not checked), at most 4 KiB. Responses are JSON, errors `{"error": "..."}`, never cached.

| Request | Answer |
|---|---|
| `POST /v1/sandboxes` `{"image": "...", "ttl": 3600}` | `201`, see below. `ttl` is optional. |
| `POST /v1/sandboxes/{name}/renew` `{"ttl": 3600}` (body optional) | `200`, as for a creation, with a new token for the calling address. `409` if it would shorten the sandbox's life. |
| `DELETE /v1/sandboxes/{name}` | `204`: the token is revoked, the container removed, open sessions end. |
| `GET /v1/sandboxes` | `200`, `[{"name", "image", "status", "expires_at", "client_ip"}]`, never tokens. |

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
  "bastion_known_hosts": "[bastion.example.com]:2200 ssh-ed25519 AAAA…",
  "token": "En0K…",
  "command": "biscuit-ssh ssh --bastion bastion.example.com:2200 -t sb-6f1c….token root@sb-6f1c… -4"
}
```

`expires_at` is the first second, in Unix time, the token no longer allows. `status` is `Creating` (being pulled and started, `expires_at` then `null`), `Active`, or `Deleting` (being removed).

Images come from Docker Hub only (`alpine`, `alpine:3.20`, `bitnami/redis`, with an optional `@sha256:` digest). They must be Linux images providing `/bin/sh`, whose command keeps running (the container runs like `docker run -dit`, so images whose command is a shell do).

| Error | Meaning |
|---|---|
| `400` | Malformed request, `ttl` out of bounds, or invalid image reference; the message says which. |
| `404` | Unknown sandbox, or image not found on Docker Hub. |
| `405`, `413` | Wrong method, body over 4 KiB. |
| `409` | The sandbox is being created, or the renewal would shorten its life. |
| `422` | The image cannot be a sandbox; the message says why (no `/bin/sh`, its command exits at once, no Linux variant). |
| `429` | Too many sandboxes, or creations in progress: retry later. |
| `502` | Docker Hub failed or the pull timed out: retry later. |
| `503` | Docker failed: retry later. |

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
host_key = "ssh-ed25519 AAAA..."   # the bastion's host public key (its host key's .pub)

[tls]
certificate = "/etc/biscuit-ssh/tls.crt"
key = "/etc/biscuit-ssh/tls.key"
```

Optional settings, with their defaults, at the top level (before any `[section]`): `label = "biscuit-ssh.sandbox"` (the bastion's `[containers] label`), `account = "root"`, `socket = "/var/run/docker.sock"`; under `[limits]`: `lifetime = 3600` (longest and default `ttl`), `max_sandboxes = 5`, `max_creations = 2`, `memory_mb = 512`, `cpus = 1.0`, `pids = 256`, `pull_timeout = 300` (seconds), and `disk_mb` (unset: see below).

The disk used by images and by writes inside containers is not bounded by default. Give Docker a filesystem of its own (its `data-root`) so a sandbox cannot fill the host's, and, where Docker's storage supports it (overlay2 on XFS with project quotas), set `limits.disk_mb` to cap each container's writes.

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

After a restart, the service first finishes what it left: interrupted creations are undone, pending deletions completed, and containers of its own it does not know removed. It never touches other containers.

## Security model

- Clients are identified by address only, and share every sandbox. An address is not a person; put the service behind a network you control.
- The sandbox signs tokens with a key that only reaches containers: a leaked sandbox key does not give access to the bastion's servers. The service and the bastion still hold Docker access, which a compromise of either turns into root on the host.
- The revocation list is the service's own: revoke a sandbox with `DELETE`, not by editing the file.
- Commands running in a container stop when the container is removed, not when a session is cut.

## Development

Separate Cargo workspace; see [AGENTS.md](../AGENTS.md). End-to-end scenarios against a running service and bastion: [`tests/e2e.sh`](tests/e2e.sh).
