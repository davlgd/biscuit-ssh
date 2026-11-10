#!/usr/bin/env bash
# End-to-end scenarios against a real deployment: an issuer, and a server whose
# sshd trusts its CA. Run from the repository root:
#
#   E2E_HOST=203.0.113.10 E2E_ADMIN=admin@test-server E2E_ROOT_KEY=root.key \
#   E2E_ISSUER_CA=issuer-ca.crt E2E_SERVER=web-1 E2E_SSH_PORT=2222 \
#   E2E_USER=deploy E2E_OTHER_USER=other E2E_REVOKED=/etc/biscuit-ssh/revoked \
#   E2E_SSHD_UNIT=sshd-e2e tests/e2e.sh
#
# E2E_SSH_PORT and E2E_SSHD_UNIT designate an sshd dedicated to these tests,
# never the one used to administer the server. The issuer is reached at
# E2E_ISSUER, https://E2E_HOST:8443 by default, and E2E_SERVER defaults to
# `test`.
#
# The server needs two accounts, E2E_USER and E2E_OTHER_USER, whose principals
# files list `E2E_SERVER:<account>`. E2E_ADMIN is an SSH destination with sudo
# on the server, used to edit the revocation list E2E_REVOKED (restored on
# exit) and read the logs of the E2E_SSHD_UNIT systemd unit.
#
# With E2E_BASTION (host:port), the bastion is tested too: it must relay
# E2E_BASTION_SERVER, a server it alone can reach at E2E_BASTION_TARGET
# (host:port, checked unreachable from here), where the same two accounts
# accept the principals `E2E_BASTION_SERVER:<account>`. The bastion must use
# the root key E2E_ROOT_KEY signs with, and read E2E_REVOKED as its revocation
# list, with a session_check_interval of at most 10 seconds. The check that nothing
# keeps running after a cut looks at processes on E2E_ADMIN, so it assumes
# that host is the relayed server.
set -uo pipefail
die() { echo "setup failed: $*" >&2; exit 1; }
for tool in cargo ssh scp sftp ssh-keygen nc cmp realpath; do
    command -v "$tool" >/dev/null || die "$tool is required"
done

: "${E2E_HOST:?address of the server}"
: "${E2E_ADMIN:?SSH destination with sudo on the server}"
: "${E2E_ROOT_KEY:?Biscuit root private key file}"
E2E_SERVER=${E2E_SERVER:-test}
: "${E2E_SSH_PORT:?port of the server's sshd}"
: "${E2E_USER:?account the principals allow}"
: "${E2E_OTHER_USER:?another account on the server}"
: "${E2E_REVOKED:?revocation list path on the server}"
: "${E2E_SSHD_UNIT:?systemd unit of the server's sshd}"
export BISCUIT_SSH_ISSUER=${E2E_ISSUER:-https://$E2E_HOST:8443}

cargo build --release --quiet -p biscuit-ssh --features certificates || die "build"
B=$PWD/target/release/biscuit-ssh
ROOT_KEY=$(realpath "$E2E_ROOT_KEY")
ISSUER_CA=()
[[ -n ${E2E_ISSUER_CA:-} ]] && ISSUER_CA=(--issuer-ca "$(realpath "$E2E_ISSUER_CA")")

WORK=$(mktemp -d) || die "mktemp"
ssh -o BatchMode=yes "$E2E_ADMIN" "sudo cat $E2E_REVOKED" >"$WORK/revoked.orig" || die "cannot read $E2E_REVOKED"
remote="" remote_file=""
restore() {
    local status=$?
    jobs -p | xargs kill 2>/dev/null
    [[ -S $WORK/mux ]] && ssh -S "$WORK/mux" -O exit x 2>/dev/null
    [[ -n $remote ]] && ssh -o BatchMode=yes "$E2E_ADMIN" "rm -rf '$remote'"
    [[ -n $remote_file ]] && ssh -o BatchMode=yes "$E2E_ADMIN" "sudo rm -f '$remote_file'"
    if ssh -o BatchMode=yes "$E2E_ADMIN" "sudo tee $E2E_REVOKED >/dev/null" <"$WORK/revoked.orig"; then
        rm -rf "$WORK"
    else
        echo "ERROR: could not restore $E2E_REVOKED, original kept in $WORK/revoked.orig" >&2
        status=1
    fi
    exit "$status"
}
trap restore EXIT
trap 'exit 130' INT TERM
cd "$WORK" || die "cd"
ssh-keygen -q -t ed25519 -N "" -C e2e -f id_test || die "ssh-keygen"
ssh-keygen -q -t ed25519 -N "" -C other -f other_key || die "ssh-keygen"

# Only the test key and its certificate: no agent, no multiplexing, no other method.
OPTS=(-p "$E2E_SSH_PORT" -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none
      -o PreferredAuthentications=publickey -o ControlMaster=no -o ControlPath=none
      -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$WORK/known_hosts" -o ConnectTimeout=10 -i id_test)
SSH=(ssh "${OPTS[@]}" "$E2E_USER@$E2E_HOST")

pass=0 fail=0
ok() { echo "PASS  $1"; pass=$((pass + 1)); }
ko() { echo "FAIL  $1"; fail=$((fail + 1)); }
expect_ok() {
    local name=$1; shift
    if out=$("$@" 2>&1); then ok "$name"; else ko "$name: $out"; fi
}
expect_fail() {
    local name=$1 pattern=$2; shift 2
    if out=$("$@" 2>&1); then ko "$name (unexpected success: $out)"
    elif grep -q -- "$pattern" <<<"$out"; then ok "$name"
    else ko "$name (wrong error: $out)"; fi
}
login() { "$B" login "$E2E_SERVER" "$E2E_USER" -i id_test "${ISSUER_CA[@]}" "$@"; }
mint() { "$B" admin mint -k "$ROOT_KEY" "$@" || die "mint $*"; }
attenuate() { "$B" token attenuate "$@" || die "attenuate $*"; }
revoke() { ssh -o BatchMode=yes "$E2E_ADMIN" "echo '$1' | sudo tee $E2E_REVOKED >/dev/null" || die "revoke"; }
revoked_id() {
    local id
    id=$("$B" token inspect -t "$1" | sed -n "s/^# block $2, revocation id //p")
    [[ -n $id ]] || die "no revocation id for block $2 of $1"
    echo "$id"
}

mint -r "$E2E_SERVER:$E2E_USER" --ttl 1h >token

expect_fail "no certificate: ssh refused" "Permission denied" "${SSH[@]}" true
expect_ok "valid token: login" login -t token
expect_ok "valid token: ssh" "${SSH[@]}" true
# OPTS without its trailing `-i id_test`: biscuit-ssh passes the identity itself.
out=$("$B" ssh -t token -i id_test "${ISSUER_CA[@]}" --server "$E2E_SERVER" "$E2E_USER@$E2E_HOST" \
    "${OPTS[@]:0:${#OPTS[@]}-2}" -- 'echo via-$(id -un)' 2>&1)
if grep -q "via-$E2E_USER" <<<"$out"; then ok "biscuit-ssh ssh: login and connect"; else ko "biscuit-ssh ssh: $out"; fi
client_ip=$(ssh-keygen -L -f id_test-cert.pub | sed -n 's/.*source-address \(.*\)\/[0-9]*$/\1/p')
expect_fail "certificate used for another account: refused" "Permission denied" \
    ssh "${OPTS[@]}" "$E2E_OTHER_USER@$E2E_HOST" true
expect_fail "port forwarding: refused" "prohibited" ssh "${OPTS[@]}" -W 127.0.0.1:22 "$E2E_USER@$E2E_HOST"

mint -r "other-server:$E2E_USER" >other_server
expect_fail "right for another server: denied" "403.*denied" login -t other_server
expect_fail "denial explained: rights granted listed" "grants other-server:$E2E_USER but not" login -t other_server
expect_ok "certificate for another server: issued" \
    "$B" login other-server "$E2E_USER" -i id_test "${ISSUER_CA[@]}" -t other_server
expect_fail "certificate for another server: sshd refuses principal" "Permission denied" "${SSH[@]}" true

attenuate -t token --source 198.51.100.0/24 >wrong_net
expect_fail "wrong source network: denied" "403.*denied" login -t wrong_net
expect_fail "denial explained with the failing restriction" "198.51.100.0/24" login -t wrong_net
[[ -n $client_ip ]] || die "no source-address in the first certificate"
attenuate -t token --source "$client_ip" >right_net
expect_ok "matching source network: login" login -t right_net

attenuate -t token --command uptime >cmd_only
expect_fail "command token, interactive request: denied" "403.*denied" login -t cmd_only
expect_ok "command token, matching command: login" login -t cmd_only --command uptime
out=$("${SSH[@]}" 'echo SHOULD-NOT-RUN' 2>&1)
if grep -q "load average" <<<"$out" && ! grep -q SHOULD-NOT-RUN <<<"$out"; then
    ok "forced command enforced by sshd"
else
    ko "forced command: $out"
fi

attenuate -t token --public-key other_key.pub >other_key_token
expect_fail "token bound to another SSH key: denied" "403.*denied" login -t other_key_token

mint -r "$E2E_SERVER:$E2E_USER" --ttl 20s >short
lifetime=$(login -t short 2>&1 | sed -n 's/.*valid for \([0-9]*\) s$/\1/p')
if [[ -n $lifetime ]] && ((lifetime <= 21)); then
    ok "certificate capped by token expiry (${lifetime}s)"
else
    ko "certificate outlives token: ${lifetime:-unknown}s"
fi
sleep 23
expect_fail "expired certificate: ssh refused" "Permission denied" "${SSH[@]}" true
expect_fail "expired token: denied" "403.*denied" login -t short

id=$(revoked_id right_net 1) || die "revocation id"
revoke "$id"
expect_fail "revoked attenuated token: refused" "403.*revoked" login -t right_net
expect_ok "parent of revoked token still valid" login -t token
id=$(revoked_id token 0) || die "revocation id"
revoke "$id"
expect_fail "revoked root block: derived token refused" "403.*revoked" login -t cmd_only
revoke ""

login -t token >/dev/null 2>&1 || die "login"
remote=$(ssh -o BatchMode=yes "$E2E_ADMIN" 'mktemp -d') || die "remote mktemp"
scp -q id_test id_test-cert.pub "$E2E_ADMIN:$remote/" || die "scp"
out=$(ssh -o BatchMode=yes "$E2E_ADMIN" "ssh -p $E2E_SSH_PORT -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
        -o PreferredAuthentications=publickey -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -i $remote/id_test $E2E_USER@127.0.0.1 true
    echo rc=\$?; rm -rf '$remote'" 2>&1)
if grep -q "rc=255" <<<"$out" && grep -q "Permission denied" <<<"$out"; then
    ok "certificate used from another address: refused"
else
    ko "certificate used from another address: $out"
fi
if ssh -o BatchMode=yes "$E2E_ADMIN" "sudo journalctl -u $E2E_SSHD_UNIT --since -1min --no-pager -o cat" |
    grep -q "not from a permitted source address"; then
    ok "sshd logged the source-address refusal"
else
    ko "no source-address refusal in sshd logs"
fi

expect_fail "plain http refused by client" "https" \
    "$B" login "$E2E_SERVER" "$E2E_USER" -i id_test -t token --issuer "http://$E2E_HOST:8443"

if [[ -n ${E2E_BASTION:-} ]]; then
    : "${E2E_BASTION_SERVER:?server name relayed by the bastion}"
    : "${E2E_BASTION_TARGET:?address of that server, unreachable from here}"
    via() {
        local token=$1 login=$2; shift 2
        "$B" ssh --bastion "$E2E_BASTION" -i id_test -t "$token" "$login" \
            -o UserKnownHostsFile="$WORK/known_hosts" -o StrictHostKeyChecking=accept-new "$@" </dev/null
    }
    target_host=${E2E_BASTION_TARGET%:*} target_port=${E2E_BASTION_TARGET##*:}
    [[ $E2E_BASTION_TARGET == *:* && -n $target_host && $target_port =~ ^[0-9]+$ ]] &&
        ((target_port >= 1 && target_port <= 65535)) ||
        die "E2E_BASTION_TARGET must be host:port"
    if nc -z -w 3 "$target_host" "$target_port" 2>/dev/null; then
        ko "bastion: target reachable directly"
    else
        ok "bastion: target not reachable directly"
    fi

    mint -r "$E2E_BASTION_SERVER:$E2E_USER" --ttl 1h >btoken
    login_ok="$E2E_USER@$E2E_BASTION_SERVER"
    expect_ok "bastion: exec" via btoken "$login_ok" true
    out=$(via btoken "$login_ok" 'echo out; echo err >&2; exit 42' 2>"$WORK/stderr")
    status=$?
    if [[ $out == out && $(<"$WORK/stderr") == err && $status == 42 ]]; then
        ok "bastion: stdout, stderr and exit status relayed"
    else
        ko "bastion: out=$out err=$(<"$WORK/stderr") status=$status"
    fi
    out=$(printf 'half-closed' | "$B" ssh --bastion "$E2E_BASTION" -i id_test -t btoken "$login_ok" \
        -o UserKnownHostsFile="$WORK/known_hosts" 'cat; echo " after eof"' 2>&1)
    if [[ $out == "half-closed after eof" ]]; then ok "bastion: stdin eof relayed"; else ko "bastion: stdin eof: $out"; fi
    via btoken "$login_ok" -tt 'tty >/dev/null && exit 7' >/dev/null 2>&1
    status=$?
    if ((status == 7)); then ok "bastion: terminal session"; else ko "bastion: terminal session exited $status"; fi

    # Plain ssh and sftp work too, with biscuit-ssh as askpass. Not `sftp -b`,
    # which implies BatchMode and thus no keyboard-interactive.
    askpass=(env SSH_ASKPASS="$B" SSH_ASKPASS_REQUIRE=force BISCUIT_SSH_ASKPASS_TOKEN="$(<btoken)")
    bastion_opts=(-o IdentitiesOnly=yes -o UserKnownHostsFile="$WORK/known_hosts" -o User="$login_ok")
    head -c 5000000 /dev/urandom >big
    remote_file="/tmp/biscuit-ssh-e2e-$$-$RANDOM"
    printf 'put big %s\nget %s big.down\nrm %s\n' "$remote_file" "$remote_file" "$remote_file" >batch
    if "${askpass[@]}" sftp -q -P "${E2E_BASTION##*:}" -i id_test "${bastion_opts[@]}" "${E2E_BASTION%:*}" \
        <batch >/dev/null 2>&1 && cmp -s big big.down; then
        ok "bastion: sftp transfer of 5 MB, identical"
    else
        ko "bastion: sftp transfer"
    fi
    expect_fail "bastion: port forwarding refused" "failed" via btoken "$login_ok" -W 127.0.0.1:22

    cp btoken t_long
    for _ in 1 2 3 4 5; do attenuate -t t_long --server "$E2E_BASTION_SERVER" >t_next && mv t_next t_long; done
    (($(wc -c <t_long) > 1100)) || die "attenuated token unexpectedly short"
    expect_ok "bastion: token longer than an ssh answer ($(wc -c <t_long | tr -d ' ') bytes)" via t_long "$login_ok" true

    mint -r "unknown-server:$E2E_USER" >t_unknown
    expect_fail "bastion: unknown server refused, with a reason" "access refused (denied)" \
        via t_unknown "$E2E_USER@unknown-server" true
    expect_fail "bastion: malformed login refused, with a reason" "access refused (invalid_login)" \
        via btoken "$E2E_USER@bad:name" true
    attenuate -t btoken --public-key other_key.pub >t_key
    expect_fail "bastion: token bound to another key refused" "access refused (denied)" via t_key "$login_ok" true
    expect_fail "bastion: another account refused" "access refused (denied)" \
        via btoken "$E2E_OTHER_USER@$E2E_BASTION_SERVER" true
    # Forced commands: the bastion asks for the command when the token alone
    # is refused, and sshd runs it whatever the client asks.
    attenuate -t btoken --command 'echo forced' >t_cmd
    expect_fail "bastion: command token without --command refused" "access refused (denied)" \
        via t_cmd "$login_ok" 'echo forced'
    out=$("$B" ssh --bastion "$E2E_BASTION" -i id_test -t t_cmd --command 'echo forced' "$login_ok" \
        -o UserKnownHostsFile="$WORK/known_hosts" 'echo free' </dev/null 2>&1)
    if [[ $out == forced ]]; then ok "bastion: command token runs its forced command"; else ko "bastion: forced command: $out"; fi
    expect_fail "bastion: command token, another command refused" "access refused (denied)" \
        "$B" ssh --bastion "$E2E_BASTION" -i id_test -t t_cmd --command 'echo other' "$login_ok" \
        -o UserKnownHostsFile="$WORK/known_hosts" true </dev/null
    out=$("$B" ssh --bastion "$E2E_BASTION" -i id_test -t btoken --command 'echo forced' "$login_ok" \
        -o UserKnownHostsFile="$WORK/known_hosts" -tt </dev/null 2>&1 | tr -d '\r')
    if [[ $out == forced* ]]; then ok "bastion: --command forced on a token allowing any session"; else ko "bastion: --command with a full token: $out"; fi
    # An open connection, without command, is never joined: neither through
    # the ssh configuration, nor explicitly.
    via btoken "$login_ok" -M -S "$WORK/free" -f -N
    printf 'Host *\n  ControlMaster auto\n  ControlPath %s\n' "$WORK/free" >mux_config
    out=$("$B" ssh --bastion "$E2E_BASTION" -i id_test -t btoken --command 'echo forced' "$login_ok" \
        -F mux_config -o UserKnownHostsFile="$WORK/known_hosts" 'echo free' </dev/null 2>&1)
    if [[ $out == forced ]]; then ok "bastion: --command never joins a configured master"; else ko "bastion: --command with a configured master: $out"; fi
    expect_fail "bastion: --command refuses explicit multiplexing" "connection of its own" \
        "$B" ssh --bastion "$E2E_BASTION" -i id_test -t btoken --command 'echo forced' "$login_ok" -S "$WORK/free" 'echo free'
    ssh -S "$WORK/free" -O exit x >/dev/null 2>&1
    expect_fail "bastion: token without key refused" "Permission denied" \
        "${askpass[@]}" ssh -p "${E2E_BASTION##*:}" -o PubkeyAuthentication=no "${bastion_opts[@]}" \
        "${E2E_BASTION%:*}" true

    # Channels on one connection: one ends without disturbing the others,
    # and expiry cuts all of those still active.
    mint -r "$E2E_BASTION_SERVER:$E2E_USER" --ttl 25s >t_mux
    expiry=$(($(date +%s) + 25))
    via t_mux "$login_ok" -M -S "$WORK/mux" -f -N
    mux=(ssh -S "$WORK/mux" -o UserKnownHostsFile="$WORK/known_hosts" x)
    "${mux[@]}" 'sleep 120' >/dev/null 2>&1 &
    first=$!
    "${mux[@]}" 'sleep 120' >/dev/null 2>&1 &
    second=$!
    sleep 2
    out=$("${mux[@]}" 'echo third' 2>&1)
    if [[ $out == third ]] && kill -0 "$first" "$second" 2>/dev/null; then
        ok "bastion: channels independent on one connection"
    else
        ko "bastion: multiplexing: $out"
    fi
    wait "$first" "$second"
    ended=$(($(date +%s) - expiry))
    if ((ended >= 0 && ended <= 2)); then ok "bastion: expiry cuts every active channel (${ended}s)"; else ko "bastion: cut ${ended}s after expiry"; fi
    ssh -S "$WORK/mux" -O exit x >/dev/null 2>&1
    left=$(ssh -o BatchMode=yes "$E2E_ADMIN" "pgrep -u $E2E_USER -f 'sleep 120' || true")
    if [[ -z $left ]]; then ok "bastion: nothing left running on the target"; else ko "bastion: processes left: $left"; fi

    mint -r "$E2E_BASTION_SERVER:$E2E_USER" --ttl 1h >t_rev
    id=$(revoked_id t_rev 0) || die "revocation id"
    via t_rev "$login_ok" 'echo started; sleep 60; echo finished' >session.out 2>&1 &
    session=$!
    for _ in $(seq 20); do
        grep -q started session.out && break
        sleep 0.5
    done
    if grep -q started session.out; then
        revoke "$id"
        revoked_at=$(date +%s)
        wait "$session"
        ended=$(($(date +%s) - revoked_at))
        if ((ended <= 12)) && ! grep -q finished session.out; then
            ok "bastion: revocation cuts the session (${ended}s)"
        else
            ko "bastion: revocation cut after ${ended}s: $(<session.out)"
        fi
    else
        kill "$session" 2>/dev/null
        ko "bastion: revocation test session did not start: $(<session.out)"
    fi
    revoke ""
    expect_fail "bastion: expired token refused" "access refused (denied)" via t_mux "$login_ok" true
fi

echo "---- $pass passed, $fail failed"
((fail == 0))
