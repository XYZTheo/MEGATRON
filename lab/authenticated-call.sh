#!/bin/bash
#
# MEGATRON lab — a customer logs in and places a call, end to end.
#
# Everything before this proved the pieces separately: rating, authorization,
# settlement, media, and login. This is the whole business in one script --
# trunk in, rate, authenticate, trunk out, bill -- which is the one-line
# description of v1 in docs/PRODUCT.md.
#
#   1  provisioning creates a customer on a plan and generates a password
#   2  provisioning renders that customer into the switch's credential file
#   3  the softphone registers with that password
#   4  the softphone places a call, authenticating again as a proxy client
#   5  the switch bills the AUTHENTICATED account, not the one From claims
#   6  the balance moves by exactly the amount the rate says
#
# Step 5 is the point. Every other step is machinery for making it true.
#
# Assumes OpenSIPS is already running with opensips-lab-auth.cfg. Run
# register-test.sh first if that is in doubt.

set -u

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=${MEGATRON_REPO:-$HOME/MEGATRON}
REALM=sip.megatron.local
SUBSCRIBER=/etc/opensips/dbtext/subscriber

export MEGATRON_DB_URL="jdbc:sqlite:/home/ubuntu/megatron-auth.db"
export MEGATRON_OPERATOR_TOKEN="lab-operator-token-at-least-32-chars-long"
export MEGATRON_SUBSCRIBER_FILE="$SUBSCRIBER"
export MEGATRON_SIP_REALM="$REALM"
export MEGATRON_SUBSCRIBER_INTERVAL_SECONDS=5

PROV=http://127.0.0.1:8081
OP=(-H "Authorization: Bearer $MEGATRON_OPERATOR_TOKEN" -H "Content-Type: application/json")

step()  { echo; echo "=== $* ==="; }
fatal() { echo "FAILED: $*" >&2; exit 1; }
jget()  { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)" 2>/dev/null; }

step "0. build and start the services"

cd "$REPO" || fatal "no repo at $REPO"
./gradlew :provisioning:installDist :switch-api:installDist \
    --console=plain --no-daemon -q 2>&1 | tail -3

pkill -f 'provisioning/bin/provisioning' 2>/dev/null
pkill -f 'switch-api/bin/switch-api' 2>/dev/null
sleep 1
rm -f /home/ubuntu/megatron-auth.db

# Provisioning owns the credential file, so it must be able to write it. Root
# owns the directory because OpenSIPS reads it; this is the lab making them
# meet. In production they are the same decision made by the installer.
sudo mkdir -p "$(dirname "$SUBSCRIBER")"
sudo chown ubuntu "$(dirname "$SUBSCRIBER")"

MEGATRON_PROVISIONING_PORT=8081 \
    nohup provisioning/build/install/provisioning/bin/provisioning >/tmp/prov.log 2>&1 &
MEGATRON_SWITCH_API_PORT=8082 \
    nohup switch-api/build/install/switch-api/bin/switch-api >/tmp/switch.log 2>&1 &

for _ in $(seq 1 40); do
    p=$(curl -s -m 2 -o /dev/null -w '%{http_code}' "${OP[@]}" "$PROV/v1/customers" 2>/dev/null)
    s=$(curl -s -m 2 -o /dev/null -w '%{http_code}' http://127.0.0.1:8082/v1/health 2>/dev/null)
    [ "$p" = "200" ] && [ "$s" = "200" ] && break
    sleep 1
done
[ "${p:-}" = "200" ] || { tail -20 /tmp/prov.log; fatal "provisioning did not come up"; }
[ "${s:-}" = "200" ] || { tail -20 /tmp/switch.log; fatal "switch-api did not come up"; }
echo "provisioning and switch-api are up"

step "1. a plan, a rate, and a customer"

PLAN=$(curl -s -m 5 "${OP[@]}" -H "Idempotency-Key: auth-plan-$$" \
    -d '{"name":"Lab Retail","currency":"USD"}' "$PROV/v1/plans" | jget 'd["id"]')
[ -n "$PLAN" ] || fatal "no plan created"

# One prefix, priced so the arithmetic is checkable by hand: 1 US cent per
# minute in 60-second increments. Any answered call under a minute therefore
# costs exactly 10000 micro-units, and a different number means the rate table
# and the rating engine disagree.
curl -s -m 5 "${OP[@]}" -H "Idempotency-Key: auth-rates-$$" -X PUT \
    -d '{"rates":[{"prefix":"1","description":"US","sell_micros_per_minute":10000,
         "connect_fee_micros":0,"increment_seconds":60,"minimum_seconds":0}]}' \
    "$PROV/v1/plans/$PLAN/rates" > /dev/null

CUST=$(curl -s -m 5 "${OP[@]}" -H "Idempotency-Key: auth-cust-$$" \
    -d "{\"handle\":\"labdialer\",\"plan_id\":\"$PLAN\",\"opening_balance_micros\":5000000}" \
    "$PROV/v1/customers")
CUST_ID=$(echo "$CUST" | jget 'd["customer"]["id"]')
PASSWORD=$(echo "$CUST" | jget 'd["credentials"]["sip_password"]')
[ -n "$PASSWORD" ] || fatal "no password issued: $CUST"
echo "customer $CUST_ID on plan $PLAN, balance 5000000u"

step "2. the credential reaches the switch"

# Waiting for provisioning to export it, rather than writing it here. If the
# service is not actually exporting, this fails -- instead of passing against
# a file the test wrote itself.
for _ in $(seq 1 30); do
    grep -q '^labdialer:' "$SUBSCRIBER" 2>/dev/null && break
    sleep 1
done
grep -q '^labdialer:' "$SUBSCRIBER" 2>/dev/null \
    || { tail -10 /tmp/prov.log; fatal "provisioning never exported labdialer"; }
echo "labdialer is in $SUBSCRIBER"

# db_text is cached in memory at load. Without a reload the switch is still
# serving the table as it was at startup, and the new customer cannot log in.
curl -s --max-time 5 http://127.0.0.1:8888/mi -H 'Content-Type: application/json' \
     -d '{"jsonrpc":"2.0","id":1,"method":"dbt_reload"}' > /dev/null
echo "asked the switch to reload it"

step "3. the softphone registers"

printf 'SEQUENTIAL\n%s;labdialer\n' "$REALM" > /tmp/lab-reg.csv
timeout 25 sipp -sf "$HERE/sipp-register.xml" 127.0.0.1:5060 \
    -inf /tmp/lab-reg.csv -au labdialer -ap "$PASSWORD" \
    -m 1 -r 1 -timeout 10 -trace_err -error_file /tmp/lab-reg.err > /dev/null 2>&1 \
    || { sed -n '1,12p' /tmp/lab-reg.err; fatal "registration failed with the issued password"; }
echo "registered"

balance() {
    curl -s -m 5 "${OP[@]}" "$PROV/v1/customers/$CUST_ID" | jget 'd["balance_micros"]'
}

before=$(balance)
echo "balance before: $before"

step "4. an authenticated call"

# A UAS to answer it. Without one the INVITE has nowhere to go and the test
# measures the switch's timeout rather than its billing.
timeout 60 sipp -sn uas -p 5070 -m 1 -bg > /dev/null 2>&1
sleep 1

printf 'SEQUENTIAL\n%s;labdialer;12125551234\n' "$REALM" > /tmp/lab-call.csv
timeout 60 sipp -sf "$HERE/sipp-call-authenticated.xml" 127.0.0.1:5060 \
    -inf /tmp/lab-call.csv -au labdialer -ap "$PASSWORD" \
    -m 1 -r 1 -timeout 40 -trace_err -error_file /tmp/lab-call.err \
    > /tmp/lab-call.log 2>&1
rc=$?
pkill -f 'sipp -sn uas' 2>/dev/null
if [ $rc -ne 0 ]; then
    echo "--- sipp errors ---"; sed -n '1,15p' /tmp/lab-call.err 2>/dev/null
    echo "--- switch log ---"
    sudo journalctl -t opensips --since '-1 min' | grep MEGATRON | tail -15
    fatal "the authenticated call did not complete"
fi
echo "call completed"

step "5. the balance moved, by the right amount"

sleep 2
after=$(balance)
echo "balance after:  $after"

[ "$after" != "$before" ] || {
    sudo journalctl -t opensips --since '-1 min' | grep MEGATRON | tail -15
    fatal "the call was placed and nothing was billed"
}

spent=$((before - after))
echo "spent ${spent}u"
[ "$spent" -eq 10000 ] \
    || fatal "expected 10000u for one 60s increment, billed ${spent}u"

step "6. it was billed to who they PROVED they are"

# The whole reason authentication is on the call path. If the switch had used
# the From header, this would still pass -- they match here -- so the negative
# case lives in register-test.sh, where From is deliberately somebody else.
sudo journalctl -t opensips --since '-1 min' | grep -q 'allow labdialer' \
    || fatal "the switch did not authorize labdialer by its authenticated identity"
echo "authorized as labdialer"

echo
echo "=== the whole business ran: login, call, bill ==="
sudo journalctl -t opensips --since '-1 min' | grep MEGATRON | tail -8
