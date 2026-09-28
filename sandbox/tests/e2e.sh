#!/usr/bin/env bash
# End-to-end scenarios against a running sandbox service and bastion. Run from
# the repository root, with the biscuit-ssh client built (cargo build --release):
#
#   E2E_API=https://sandbox.example.com:8444 E2E_API_CA=ca.crt \
#   E2E_BASTION=bastion.example.com:2200 E2E_ADMIN=admin@sandbox-host \
#   E2E_SANDBOX_KEY=/etc/biscuit-ssh/sandbox.key E2E_ROOT_KEY=root.key \
#   E2E_SERVER=web-1 E2E_SERVER_USER=deploy sandbox/tests/e2e.sh
#
# E2E_ADMIN is an SSH destination with sudo on the host running the service,
# Docker and the bastion: requests from there come from a non-allowed address.
# E2E_SANDBOX_KEY is the sandbox signing key on that host, E2E_ROOT_KEY the
# main root key here, and E2E_SERVER a server the bastion relays over SSH,
# where E2E_SERVER_USER exists: both check that each key only reaches its own
# kind of target. The service's lifetime must allow a 60 s sandbox.
#
# Recovery scenarios stop and start the service: E2E_UNIT is its systemd unit,
# E2E_STATE_DIR its state_dir, E2E_LABEL its label (default below).
set -uo pipefail
die() { echo "setup failed: $*" >&2; exit 1; }

: "${E2E_API:?sandbox API URL}"
: "${E2E_BASTION:?bastion host:port}"
: "${E2E_ADMIN:?SSH destination with sudo on the service host}"
: "${E2E_SANDBOX_KEY:?sandbox signing key path on the service host}"
: "${E2E_ROOT_KEY:?main Biscuit root private key file}"
: "${E2E_SERVER:?server relayed over SSH by the bastion}"
: "${E2E_SERVER_USER:?account on that server}"
: "${E2E_UNIT:?systemd unit of the sandbox service}"
: "${E2E_STATE_DIR:?state_dir of the sandbox service}"
E2E_LABEL=${E2E_LABEL:-biscuit-ssh.sandbox}
for tool in cargo curl ssh ssh-keygen python3; do
    command -v "$tool" >/dev/null || die "$tool is required"
done
B=$PWD/target/release/biscuit-ssh
[[ -x $B ]] || die "build the client first: cargo build --release"
ROOT_KEY=$(realpath "$E2E_ROOT_KEY")
CURL=(curl -s --max-time 300)
[[ -n ${E2E_API_CA:-} ]] && CURL+=(--cacert "$(realpath "$E2E_API_CA")")

WORK=$(mktemp -d) || die "mktemp"
created=()
cleanup() {
    local status=$?
    for name in "${created[@]}"; do
        "${CURL[@]}" -X DELETE "$E2E_API/v1/sandboxes/$name" >/dev/null
    done
    rm -rf "$WORK"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
cd "$WORK" || die "cd"
ssh-keygen -q -t ed25519 -N "" -C e2e -f id_test || die "ssh-keygen"

pass=0 fail=0
ok() { echo "PASS  $1"; pass=$((pass + 1)); }
ko() { echo "FAIL  $1"; fail=$((fail + 1)); }
check() { if eval "$2"; then ok "$1"; else ko "$1 ($3)"; fi; }
api() { # method path [json] → body in $WORK/body, status in $code
    local data=()
    [[ $# -ge 3 ]] && data=(-H 'content-type: application/json' -d "$3")
    code=$("${CURL[@]}" -X "$1" "${data[@]}" -o body -w '%{http_code}' "$E2E_API$2")
}
field() { python3 -c "import json,sys; print(json.load(open('body'))['$1'])"; }
via() { # token login [ssh args…]
    local token=$1 login=$2; shift 2
    "$B" ssh --bastion "$E2E_BASTION" -t "$token" -i id_test "$login" -o LogLevel=ERROR \
        -o UserKnownHostsFile="$WORK/known_hosts" -o StrictHostKeyChecking=accept-new "$@" </dev/null
}
create() { # image [ttl] → name in $name, token in token.$name
    local body="{\"image\":\"$1\"${2:+,\"ttl\":$2}}"
    api POST /v1/sandboxes "$body"
    [[ $code == 201 ]] || return 1
    name=$(field name)
    created+=("$name")
    field token >"token.$name"
}
others() { ssh -o BatchMode=yes "$E2E_ADMIN" "docker ps -a --format '{{.Names}}' | grep -v '^sb-' | sort"; }
exists() { ssh -o BatchMode=yes "$E2E_ADMIN" "docker inspect $1 >/dev/null 2>&1"; }

before=$(others)

# Only allowed addresses get anything but a generic 401, whatever the request.
api_host=$(python3 -c "import urllib.parse,sys; u=urllib.parse.urlparse(sys.argv[1]); print(u.hostname, u.port)" "$E2E_API")
read -r host port <<<"$api_host"
for request in "GET /v1/sandboxes" "POST /v1/sandboxes" "DELETE /v1/sandboxes/x" "GET /nowhere"; do
    read -r method path <<<"$request"
    out=$(ssh -o BatchMode=yes "$E2E_ADMIN" \
        "curl -sk -X $method -d '{bad' -o - -w ' %{http_code}' https://$host:$port$path")
    check "unknown address: $request → 401 without detail" \
        '[[ $out == "{\"error\":\"authentication failed\"} 401" ]]' "$out"
done

api POST /v1/sandboxes '{bad'
check "malformed body → 400" '[[ $code == 400 ]]' "$code"
api POST /v1/sandboxes '{"image":"alpine","extra":1}'
check "unknown field → 400" '[[ $code == 400 ]]' "$code"
api POST /v1/sandboxes '{"image":"ghcr.io/owner/image"}'
check "other registry → 400" '[[ $code == 400 ]]' "$code"
api POST /v1/sandboxes '{"image":"alpine","ttl":30}'
check "ttl out of bounds → 400" '[[ $code == 400 ]]' "$code"
api POST /v1/sandboxes "{\"image\":\"biscuitssh/no-such-image-$RANDOM$RANDOM\"}"
check "unknown image → 404" '[[ $code == 404 && $(field error) == "image not found" ]]' "$code $(cat body)"
api POST /v1/sandboxes '{"image":"hello-world"}'
check "image that exits at once → 422, nothing left" '[[ $code == 422 ]]' "$code $(cat body)"

create alpine:3.20 || die "cannot create a sandbox: $code $(cat body)"
first=$name
out=$(via "token.$first" "root@$first" 'echo out; echo err >&2; exit 42' 2>err)
status=$?
check "session: stdout, stderr, exit status" '[[ $out == out && $(<err) == err && $status == 42 ]]' "$out/$(<err)/$status"
out=$(printf 'half' | "$B" ssh --bastion "$E2E_BASTION" -t "token.$first" -i id_test "root@$first" \
    -o UserKnownHostsFile="$WORK/known_hosts" 'cat; echo " closed"' 2>&1)
check "session: stdin EOF" '[[ $out == "half closed" ]]' "$out"
out=$(via "token.$first" "root@$first" -tt 'sleep 0.5; tty' 2>/dev/null | tr -d '\r')
check "session: terminal" '[[ $out == /dev/pts/* ]]' "$out"
out=$(via "token.$first" "root@$first" 'ls /sys/class/net' 2>&1)
check "container has no network" '[[ $out == lo ]]' "$out"
out=$(via "token.$first" "root@$first" -s sftp 2>&1)
check "no subsystems (sftp)" '[[ $? != 0 ]]' "$out"

scp -q id_test "token.$first" "$E2E_ADMIN:/tmp/" || die "scp"
out=$(ssh -o BatchMode=yes "$E2E_ADMIN" "chmod 600 /tmp/id_test; biscuit-ssh ssh --bastion $E2E_BASTION \
    -t /tmp/token.$first -i /tmp/id_test root@$first -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    true </dev/null 2>&1; rm -f /tmp/id_test /tmp/token.$first")
check "token used from another address → refused" '[[ $out == *"access refused (denied)"* ]]' "$out"

"$B" admin mint -k "$ROOT_KEY" -r "$first:root" --ttl 5m >main.token 2>/dev/null
out=$(via main.token "root@$first" true 2>&1)
check "main root key cannot reach a container" '[[ $out == *"access refused"* ]]' "$out"
ssh -o BatchMode=yes "$E2E_ADMIN" "sudo biscuit-ssh admin mint -k $E2E_SANDBOX_KEY \
    -r $E2E_SERVER:$E2E_SERVER_USER --ttl 5m" >sandbox-key.token 2>/dev/null
out=$(via sandbox-key.token "$E2E_SERVER_USER@$E2E_SERVER" true 2>&1)
check "sandbox key cannot reach a server" '[[ $out == *"access refused"* ]]' "$out"

code=$("${CURL[@]}" -X POST -H 'Content-Type:' --data-binary garbage -o body -w '%{http_code}' \
    "$E2E_API/v1/sandboxes/$first/renew")
check "renew with an invalid body → 400" '[[ $code == 400 ]]' "$code"
out=$(via "token.$first" "root@$first" 'grep CapEff /proc/self/status' 2>&1)
check "reduced capabilities" '[[ $out == "CapEff:"*"00000000000000fb" ]]' "$out"
cp "token.$first" "old.$first"
api POST "/v1/sandboxes/$first/renew" '{"ttl":3600}'
check "renew → 200" '[[ $code == 200 ]]' "$code $(cat body)"
field token >"token.$first"
out=$(via "token.$first" "root@$first" 'echo renewed' 2>&1)
check "renewed token works" '[[ $out == renewed ]]' "$out"
out=$(via "old.$first" "root@$first" true 2>&1)
check "previous token revoked" '[[ $out == *"access refused (revoked)"* ]]' "$out"
api POST "/v1/sandboxes/$first/renew" '{"ttl":60}'
check "renewal that would shorten → 409" '[[ $code == 409 ]]' "$code"

via "token.$first" "root@$first" 'echo started; sleep 60; echo finished' >session.out 2>&1 &
session=$!
sleep 3
api DELETE "/v1/sandboxes/$first"
check "delete → 204" '[[ $code == 204 ]]' "$code $(cat body)"
deleted_at=$(date +%s)
wait "$session"
check "delete ends the open session" '(($(date +%s) - deleted_at <= 12)) && ! grep -q finished session.out' \
    "$(<session.out)"
check "delete removes the container" '! exists "$first"' "still there"
out=$(via "token.$first" "root@$first" true 2>&1)
check "deleted sandbox refuses its token" '[[ $out == *"access refused"* ]]' "$out"
api DELETE "/v1/sandboxes/$first"
check "delete again → 404" '[[ $code == 404 ]]' "$code"

create alpine:3.20 60 || die "cannot create a short sandbox: $code $(cat body)"
short=$name
expires_at=$(field expires_at)
now=$(date +%s)
sleep $((expires_at - now + 12))
api GET /v1/sandboxes
check "expired sandbox reaped" '! grep -q "$short" body && ! exists "$short"' "$(cat body)"
out=$(via "token.$short" "root@$short" true 2>&1)
check "expired token refused" '[[ $out == *"access refused"* ]]' "$out"

# Recovery: containers of this instance unknown to the state are removed;
# those of another instance are left alone; interrupted creations undone.
admin() { ssh -o BatchMode=yes "$E2E_ADMIN" "$@"; }
instance=$(admin "sudo python3 -c 'import json; print(json.load(open(\"$E2E_STATE_DIR/state.json\"))[\"instance\"])'")
[[ -n $instance ]] || die "cannot read the instance identifier"
stray=sb-stray-$RANDOM foreign=sb-foreign-$RANDOM
admin "docker run -d --network none --label $E2E_LABEL=$instance --name $stray alpine:3.20 sleep 600 >/dev/null" &&
    admin "docker run -d --network none --label $E2E_LABEL=someone-else --name $foreign alpine:3.20 sleep 600 >/dev/null" ||
    die "cannot start the recovery containers"
sleep 15
check "stray container of this instance removed" '! exists "$stray"' "still there"
check "container of another instance left alone" 'exists "$foreign"' "removed"
admin "docker rm -f $foreign >/dev/null"

interrupted=sb-interrupted-$RANDOM
admin "sudo systemctl stop $E2E_UNIT &&
    docker run -d --network none --label $E2E_LABEL=$instance --name $interrupted alpine:3.20 sleep 600 >/dev/null &&
    sudo python3 - <<PY
import json
path = '$E2E_STATE_DIR/state.json'
state = json.load(open(path))
state['sandboxes']['$interrupted'] = {'status': 'Creating', 'image': 'docker.io/library/alpine:3.20',
    'container': None, 'image_id': None, 'token': None, 'expires_at': 0, 'client': '192.0.2.1'}
json.dump(state, open(path, 'w'))
PY
    sudo systemctl start $E2E_UNIT" || die "cannot simulate an interrupted creation"
sleep 5
api GET /v1/sandboxes
check "interrupted creation undone on restart" '! exists "$interrupted" && ! grep -q "$interrupted" body' \
    "$(cat body)"

check "other containers untouched" '[[ $(others) == "$before" ]]' "$(others)"
echo "---- $pass passed, $fail failed"
((fail == 0))
