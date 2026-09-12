#!/usr/bin/env bash
# End-to-end scenarios against a real deployment: an issuer, and a server whose
# sshd trusts its CA. Run from the repository root:
#
#   E2E_HOST=203.0.113.10 E2E_ADMIN=admin@test-server E2E_ROOT_KEY=root.key \
#   E2E_ISSUER_CA=issuer-ca.crt tests/e2e.sh
#
# The server needs two accounts, E2E_USER and E2E_OTHER_USER, whose principals
# files list `E2E_SERVER:<account>`. E2E_ADMIN is an SSH destination with sudo
# on the server, used to edit the revocation list (restored on exit) and read
# sshd logs.
set -uo pipefail
die() { echo "setup failed: $*" >&2; exit 1; }

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

cargo build --release --quiet --bin biscuit-ssh || die "build"
B=$PWD/target/release/biscuit-ssh
ROOT_KEY=$(realpath "$E2E_ROOT_KEY")
ISSUER_CA=()
[[ -n ${E2E_ISSUER_CA:-} ]] && ISSUER_CA=(--issuer-ca "$(realpath "$E2E_ISSUER_CA")")

WORK=$(mktemp -d) || die "mktemp"
ssh -o BatchMode=yes "$E2E_ADMIN" "sudo cat $E2E_REVOKED" >"$WORK/revoked.orig" || die "cannot read $E2E_REVOKED"
remote=""
restore() {
    local status=$?
    [[ -n $remote ]] && ssh -o BatchMode=yes "$E2E_ADMIN" "rm -rf '$remote'"
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
expect_fail "denial explained: no matching right" "grants no access" login -t other_server
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

echo "---- $pass passed, $fail failed"
((fail == 0))
