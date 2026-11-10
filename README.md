# biscuit-ssh

biscuit-ssh gives third parties SSH access to your servers through [Biscuit](https://www.biscuitsec.org/) tokens. You hand out a token that grants logins, such as the `deploy` account on the server `web-1`. Whoever holds it can restrict it further, offline and without any key: expiration, source networks, servers, accounts, and SSH keys.

Servers run a stock OpenSSH that only trusts a certificate authority (CA): nothing specific to Biscuit runs on them. Token holders log in to the bastion with their token. The bastion checks it, relays the session to servers only it can reach, and cuts it when access ends.

```text
holder ── ssh + token ──▶ bastion  (checks the token, again every 30 s)
                            └─────▶ server  (with a certificate the bastion signs for itself)
```

To connect to servers directly with a short-lived certificate instead, see [Certificates](https://github.com/davlgd/biscuit-ssh/blob/main/docs/certificates.md).

## Concepts

| Term                  | Meaning                                                                                                 |
| --------------------- | ------------------------------------------------------------------------------------------------------- |
| Account               | The Unix account on the server, such as `deploy`                                                        |
| Attenuation           | Adding restrictions to a token: the result never grants more than the original                          |
| Principal             | `server:account`, such as `web-1:deploy`: servers list the principals they accept for each account      |
| Revocation identifier | The identifier of a block of a token: revoking it refuses every token that contains this block          |
| Server name           | A label you choose for each server, such as `web-1`: not a DNS name, although the two often match       |
| Token                 | A Biscuit: its first block, signed with your root key, grants rights, and later blocks add restrictions |

A server name appears in the rights of tokens, in the principals files of servers, and in the configuration of the bastion. Anyone holding a token can use it: treat it as a secret.

## Quick start

With a running deployment, as [Administer a deployment](https://github.com/davlgd/biscuit-ssh/blob/main/README.md#administer-a-deployment) explains, and its root key, mint a token and log in:

```bash
ssh-keygen -t ed25519 -N "" -f ./id_test
biscuit-ssh admin mint -k root.key -r web-1:deploy --ttl 1h > my.token
biscuit-ssh ssh --bastion bastion.example.com:2200 -t my.token -i ./id_test deploy@web-1
```

## Connect with a token

You receive your token file with the address of the bastion and the fingerprint of its host key.

You also need the `biscuit-ssh` client, the OpenSSH client, and an SSH key, which the bastion requires. Build the client from source, as [Build](https://github.com/davlgd/biscuit-ssh/blob/main/README.md#build) explains. It uses `~/.ssh/id_ed25519` by default: choose another key with `-i`, or create one with `ssh-keygen -t ed25519`.

### Log in through the bastion

```bash
biscuit-ssh ssh --bastion bastion.example.com:2200 -t my.token deploy@web-1
```

The destination is `account@server`, with the server named as in the token. Arguments after the destination go to `ssh` unchanged, such as `deploy@web-1 uptime`. On the first connection, `ssh` shows the fingerprint of the bastion's host key: compare it with the one you received.

`biscuit-ssh` runs `ssh` with itself as `SSH_ASKPASS`, to answer the token prompts of the bastion, and only those. Key passphrases and host key confirmations still appear on the terminal. Plain `ssh`, `scp`, or `sftp` work the same way, with the login `account@server`:

```bash
env SSH_ASKPASS=biscuit-ssh SSH_ASKPASS_REQUIRE=force BISCUIT_SSH_ASKPASS_TOKEN="$(cat my.token)" \
  sftp -P 2200 -o User=deploy@web-1 bastion.example.com
```

`BISCUIT_SSH_ASKPASS_TOKEN` holds the token itself. `BatchMode`, which `sftp -b` sets, disables the token prompt.

The bastion only relays sessions: it refuses port, agent, and X11 forwarding, and environment variables.

### Check host keys

As with any SSH server, check a host key before you trust it: `ssh` records it in `~/.ssh/known_hosts`. To check a fingerprint you received without connecting, fetch the key, then print its fingerprint:

```bash
ssh-keyscan -p 2200 bastion.example.com > known_hosts
ssh-keygen -lf known_hosts
```

Once the fingerprint matches the one you received, pass this file to `ssh` with `-o UserKnownHostsFile=known_hosts`.

### Use it from scripts and agents

Scripts and agents have no terminal to answer prompts, so remove every reason for one:

- Pass the token with `-t FILE`, `BISCUIT_SSH_TOKEN_FILE`, or the token itself in `BISCUIT_SSH_TOKEN`
- Trust host keys beforehand, with a checked `known_hosts` file
- Bound the connection time with `-o ConnectTimeout=15`
- Give `ssh` no input with `</dev/null` when it needs none

`-t -` reads the token from standard input, leaving no input to the remote command. `-o StrictHostKeyChecking=accept-new` also avoids the host key prompt, but trusts the first key `ssh` sees.

Options before the destination go to `biscuit-ssh`, and those after it to `ssh`, where `-t` asks for a terminal.

```bash
biscuit-ssh ssh --bastion bastion.example.com:2200 -t my.token -i ./id_ed25519 deploy@web-1 \
  -o UserKnownHostsFile=./known_hosts -o ConnectTimeout=15 uptime </dev/null
```

### Force a command

A token restricted with `--command` only allows sessions forced to one of its commands, such as for a backup job. Pass the command to `biscuit-ssh ssh`, before the destination:

```bash
biscuit-ssh token attenuate -t my.token --command 'pg_dump app' > backup.token
biscuit-ssh ssh --bastion bastion.example.com:2200 -t backup.token --command 'pg_dump app' deploy@db-1
```

When the token alone doesn't allow the login, the bastion asks for a command, and `biscuit-ssh` answers with `--command`. The bastion checks the token with this command, then forces it on every session of the connection, as `sshd` does with `force-command`. The server, or the container, then runs it whatever `ssh` asks. With a token that allows any session, `--command` restricts this connection to the command.

The command controls what starts, not what this program runs next: a shell or an editor can still run anything. A token that allows interactive sessions thus allows every command. With plain `ssh`, set `BISCUIT_SSH_ASKPASS_COMMAND` to the command: the bastion only asks for it when the token requires one.

By default, each `biscuit-ssh ssh` logs in afresh, so the bastion checks the token you give, rather than one of a multiplexed connection. Explicit multiplexing options of `ssh`, `-M`, `-S`, `-O`, and `-o Control…`, still apply, except with `--command`, which refuses them. `--command` also adds a block to the token: with a sealed token, which takes no more blocks, `biscuit-ssh` fails before connecting.

### Copy files

Through the bastion, `scp`, `sftp`, and `rsync` copy files and directories to and from servers. Give them the askpass variables, the port of the bastion, and the login `account@server`:

```bash
export SSH_ASKPASS=biscuit-ssh SSH_ASKPASS_REQUIRE=force BISCUIT_SSH_ASKPASS_TOKEN="$(cat my.token)"
scp -r -P 2200 -o User=deploy@web-1 ./site bastion.example.com:/srv/
rsync -a -e "ssh -p 2200 -o User=deploy@web-1" ./site/ bastion.example.com:/srv/site/
```

Containers have no `sftp`, so `scp` and `rsync` fail there: send a directory through a session with `tar` instead. On macOS, `COPYFILE_DISABLE=1 tar --no-xattrs` leaves out the `._*` files that `tar` would add:

```bash
tar cf - ./site | biscuit-ssh ssh --bastion bastion.example.com:2200 -t my.token root@sb-6f1c 'tar xf - -C /srv'
```

### Hand access over

Restrict your token before you pass it on, then check it: `inspect` shows its blocks, their revocation identifiers, and times in UTC. Its `--json` option prints them for scripts.

```bash
biscuit-ssh token attenuate -t my.token --ttl 8h --server web-1 --source 198.51.100.0/24 > contractor.token
biscuit-ssh token inspect -t contractor.token
```

| Flag           | Restricts access to                                          |
| -------------- | ------------------------------------------------------------ |
| `--command`    | Sessions forced to this command                              |
| `--mode`       | One way in, such as `bastion`                                |
| `--public-key` | This SSH key, as a fingerprint or a `.pub` file              |
| `--server`     | This server                                                  |
| `--source`     | This network or address                                      |
| `--ttl`        | This lifetime from now, such as `90s`, `15m`, `8h`, or `30d` |
| `--user`       | This account                                                 |

Restrictions add up and never exceed your token. Repeat a flag for several values, but not `--mode` or `--ttl`.

Send the token file over a secure channel, with the account, the server name, and the expiration. Add the address of the bastion and the fingerprint of its host key. Keep the identifier of the last block: revoking it cuts this exact token.

### Troubleshooting

| Message                                              | Meaning                                                                                      |
| ---------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `access refused (busy)`                              | Too many logins at once, or token checks too slow: retry later                               |
| `access refused (denied)`                            | The token doesn't allow this login: unknown server, other account, a restriction, or expired |
| `access refused (internal)`                          | The bastion failed, such as on an unreadable revocation list: its logs tell why              |
| `access refused (invalid_command)`                   | The command must be a single printable line, of at most 1000 bytes through the bastion       |
| `access refused (invalid_login)`                     | The bastion login must be `account@server`                                                   |
| `access refused (invalid_token)`                     | Malformed token, or a token from another deployment                                          |
| `access refused (revoked)`                           | The revocation list holds an identifier of the token                                         |
| `Connection timed out`, `Connection reset by peer`   | Network: wrong address or port, a firewall, or the bastion is down                           |
| `no terminal to answer ssh's question`               | `ssh` asked for a confirmation or a passphrase, with no terminal                             |
| `Permission denied (publickey,keyboard-interactive)` | The bastion needs an SSH key before the token, and the client offered none                   |

`ssh-keyscan -p <port> <bastion>` checks that the bastion answers. When `ssh` has no terminal to ask its questions on, see [Use it from scripts and agents](https://github.com/davlgd/biscuit-ssh/blob/main/README.md#use-it-from-scripts-and-agents), which avoids every prompt.

## Administer a deployment

### Build

The build needs a stable Rust toolchain. The bastion runs on Linux, and the client on Linux and macOS:

```bash
cargo build --release
sudo install target/release/biscuit-ssh /usr/local/bin/
sudo install target/release/biscuit-ssh-bastion /usr/local/bin/
```

Install the client, `biscuit-ssh`, on the administration machine and for token holders, and the bastion, `biscuit-ssh-bastion`, where it runs.

### Create the keys

On the administration machine, create the root key, which signs tokens. The command prints its public key, `ed25519/…`, for the configuration of the bastion:

```bash
biscuit-ssh admin keygen -o root.key
```

On the machine that runs the bastion, create an unprivileged account, the CA, and an empty revocation list. The bastion uses this CA to sign the certificates it logs in to servers with.

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin biscuit-ssh
sudo install -d -m 755 /etc/biscuit-ssh
sudo ssh-keygen -t ed25519 -N "" -C biscuit-ssh-ca -f /etc/biscuit-ssh/ca
sudo chown biscuit-ssh: /etc/biscuit-ssh/ca && sudo chmod 600 /etc/biscuit-ssh/ca
sudo touch /etc/biscuit-ssh/revoked
```

> [!WARNING]
> Anyone holding the root key can grant any access, and anyone holding the CA key can log in anywhere. If one leaks, replace it, with `root_public_key` or the `TrustedUserCAKeys` of servers: every token or certificate it signed becomes invalid.

### Grant access

```bash
biscuit-ssh admin mint -k root.key -r web-1:deploy -r web-2:deploy --ttl 30d > partner.token
biscuit-ssh admin mint -k root.key -r web-1:deploy --mode bastion --ttl 8h > contractor.token
```

`-r server:account` grants a right, and the [restriction flags](https://github.com/davlgd/biscuit-ssh/blob/main/README.md#hand-access-over) apply. Without `--ttl`, the token never expires.

Mint one token per recipient, and let holders attenuate theirs to pass it on. Revoking the first block of a minted token then affects nobody else. Revoking the first block of a token shared by several people would revoke them all.

### Configure the servers

Add these lines to `sshd_config`:

```text
TrustedUserCAKeys /etc/ssh/biscuit-ssh-ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
```

`/etc/ssh/biscuit-ssh-ca.pub` is a copy of `/etc/biscuit-ssh/ca.pub`. `/etc/ssh/principals/<account>` lists the principals allowed to log in as this account, one per line, typically `<server name>:<account>`. On `web-1`, `/etc/ssh/principals/deploy` holds `web-1:deploy`.

Keep the clocks of servers synchronized: a lagging clock extends the validity of certificates. Protect servers with a firewall that lets only the bastion reach their `sshd`, so that tokens are the only way in.

### Run the bastion

Create the host key of the bastion:

```bash
sudo ssh-keygen -t ed25519 -N "" -C biscuit-ssh-bastion -f /etc/biscuit-ssh/bastion_host_key
sudo chown biscuit-ssh: /etc/biscuit-ssh/bastion_host_key
```

Write `/etc/biscuit-ssh/bastion.toml`, with a `[targets.<server name>]` section per server the bastion relays to. The bastion refuses an RSA host key of its own. The `host_key` of a target is the host public key of this server: the bastion refuses any other. The bastion negotiates Ed25519 first, then Elliptic Curve Digital Signature Algorithm (ECDSA), then RSA: give the first type the server has, such as with `ssh-keyscan -t ed25519 10.0.0.5`.

```toml
listen = "0.0.0.0:2200"
host_key = "/etc/biscuit-ssh/bastion_host_key"
root_public_key = "ed25519/..."
ca_key = "/etc/biscuit-ssh/ca"
revocation_list = "/etc/biscuit-ssh/revoked"

[targets.web-1]
address = "10.0.0.5:22"
host_key = "ssh-ed25519 AAAA..."
```

| Optional setting                | Default                                         | Meaning                                                             |
| ------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------- |
| `clock_skew`                    | `30`                                            | How far back certificates start, at most 300 s                      |
| `policy`                        | `allow if server($s), user($u), right($s, $u);` | Datalog policies of the verifier                                    |
| `revocation_list`               | None                                            | The revocation list: without it, the bastion never revokes anything |
| `session_check_interval`        | `30`                                            | Seconds between token re-evaluations, from 5 to 600                 |
| `targets.<name>.source_address` | The local address                               | The address of the bastion, as this server sees it                  |

The certificates of the bastion only accept its own address, as servers see it. Set `source_address` when network address translation hides the local address of the bastion from a server.

Check the configuration with `biscuit-ssh-bastion --check --config /etc/biscuit-ssh/bastion.toml`, as the `biscuit-ssh` account. It loads the keys, reads the revocation lists, and reaches Docker when containers are on, then exits without listening. Run `biscuit-ssh-bastion --config /etc/biscuit-ssh/bastion.toml` as this account, for example with this systemd unit:

```ini
[Service]
User=biscuit-ssh
ExecStart=/usr/local/bin/biscuit-ssh-bastion --config /etc/biscuit-ssh/bastion.toml
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
```

At startup, the bastion logs the fingerprint of its host key: give it to token holders.

#### Containers

The bastion can also reach Docker containers, which need no SSH server. A session runs in the container through `docker exec`, as the login account, with `bash` if the image has it, `sh` otherwise. Enable containers with a `[containers]` section:

```toml
[containers]
root_public_key = "ed25519/..."
revocation_list = "/var/lib/biscuit-ssh/containers.revoked"
label = "biscuit-ssh.container"
# socket = "/var/run/docker.sock"
```

A server name that isn't a configured target reaches the running container of this exact name, if it carries the label, whatever its value. Containers have their own root key, revocation list, and optional `policy`: a token signed by one root key never reaches the other kind of target. Whatever creates the containers labels them, signs their tokens, and maintains their revocation list.

Containers need a Linux image with `/bin/sh`, where the login account exists. Their sessions have no subsystems: no `sftp`, nor `scp` since OpenSSH 9.0, unless run with `-O`. A cut stops relaying, but commands already running go on until the container stops: Docker can't stop a command started with `docker exec`.

The bastion refuses to start if Docker is unreachable, or if containers share the main root key. Access to the Docker socket is equivalent to root on the host. Give it to the bastion only where you want containers, for example with `SupplementaryGroups=docker` in its unit.

### Revoke access

The revocation list is a text file with one revocation identifier per line, in hex, where blank lines and lines starting with `#` don't count. Find identifiers with `biscuit-ssh token inspect`, or in the `sshd` logs of servers, as the key ID of the bastion's certificates.

Revoking a block refuses every token that contains it: the token ending with this block, and every token derived from it. The last block identifies one exact token, and the first block the whole family.

Set `revocation_list` before you need it. The bastion reads it again at every check, and refuses everything while it's unreadable. A single malformed line makes the whole list unreadable: the bastion then refuses every login, and cuts every session. Once you add an identifier, the bastion refuses new logins with the matching tokens, and cuts their open sessions within `session_check_interval`.

### Read the logs

The bastion logs to stderr, with the verbosity `RUST_LOG` sets, and never logs tokens.

It logs each login with the client address, server, account, key fingerprint, token identifier, and forced command. It also logs each refusal with the client address and the reason, the commands and subsystems run, and the sessions it cuts, with the reason.

## Write token rules

You can also write tokens in Datalog. The bastion describes each request with the facts `time`, `source_ip`, `source_net`, `server`, `user`, `public_key`, and `mode`, plus `command` for a forced command. `source_net` holds one fact per network containing the client, from `0.0.0.0/0` to `a.b.c.d/32`, or `::/0` to `/128` for IPv6. `public_key` is the fingerprint of the holder's key, and `mode` names the way in, either `bastion` or `certificate`.

A token grants `right($server, $user)` facts in its first block, and restricts them with checks, such as `check if server($s), ["web-1"].contains($s)`. With the default policy, a request passes when every check passes and a right of the first block matches.

A `policy` of your own can trust more, such as third-party blocks signed by a key you trust. [`vocabulary.rs`](https://github.com/davlgd/biscuit-ssh/blob/main/crates/core/src/vocabulary.rs) documents the full contract.

## Security

The bastion evaluates the token for every second of a session, and stops at the first refusal. From the second the token stops allowing access, or within `session_check_interval` of a revocation, it relays nothing more. It closes both connections at most 2 seconds later.

Before closing, the bastion sends `HUP` to remote commands, on a best-effort basis. A stalled server may not receive it, and processes that detach themselves, with `nohup` or `setsid`, survive, as with any SSH disconnection.

The bastion receives tokens inside SSH, and signs certificates for itself only, valid for its own address. It fails closed on any error, such as an unreadable revocation list: it refuses access.

## Contributing

[CONTRIBUTING.md](https://github.com/davlgd/biscuit-ssh/blob/main/CONTRIBUTING.md) explains how to build, test, and document the project.

## License

Copyright 2026 davlgd. Licensed under the [Apache License, Version 2.0](https://github.com/davlgd/biscuit-ssh/blob/main/LICENSE).
