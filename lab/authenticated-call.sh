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
# Provisioning tells the switch to re-read the file. Without this the file
# changes and OpenSIPS keeps serving the table it loaded at startup, so a new
# customer can never register — see SwitchReloader.
export MEGATRON_SWITCH_MI_URL=http://127.0.0.1:8888/mi

PROV=http://127.0.0.1:8081
OP=(-H "Authorization: Bearer $MEGATRON_OPERATOR_TOKEN" -H "Content-Type: application/json")

step()  { echo; echo "=== $* ==="; }
fatal() { echo "FAILED: $*" >&2; exit 1; }
jget()  { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)" 2>/dev/null; }

step "0. build and start the services"

cd "$REPO" || fatal "no repo at $REPO"
./gradlew :provisioning:installDist :switch-api:installDist \
    --console=plain --no-daemon -q 2>&1 | tail -3

# KILL THE JVM, NOT THE WRAPPER.
#
# installDist produces a shell script that execs java, so pkill -f on the
# script's path matches nothing that is still running. The old process kept
# port 8081 and the database file, the new one failed to start, and the health
# check passed -- against the process we meant to replace. The run then failed
# much later with "handle already exists", which reads like a test bug rather
# than a stale service.
pkill -f 'net.megatron.provisioning.MainKt' 2>/dev/null
pkill -f 'net.megatron.switchapi.MainKt' 2>/dev/null
pkill -f 'install/provisioning' 2>/dev/null
pkill -f 'install/switch-api' 2>/dev/null
# Match the JVM specifically -- `java ... net.megatron.<x>.MainKt` -- not the
# bare string. A plain `pgrep -f net.megatron` also matches any shell command
# that happens to mention it, including a grep over the service's own log, and
# then this guard reports a stale service that does not exist and refuses to
# run at all.
running() { pgrep -f 'java.*net\.megatron\.' >/dev/null; }
for _ in $(seq 1 10); do
    running || break
    sleep 1
done
running && fatal "a previous service would not stop: $(pgrep -af 'java.*net\.megatron\.')"

# -wal and -shm too: SQLite recovers from them, so removing only the .db
# leaves the previous run's customers in place.
rm -f /home/ubuntu/megatron-auth.db /home/ubuntu/megatron-auth.db-wal \
      /home/ubuntu/megatron-auth.db-shm

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

step "1. a carrier, a plan, a rate, and a customer"

# WHERE CALLS GO. The switch asks the authorizer per call and refuses when
# there is no enabled outbound trunk -- allowing it would reserve balance
# against a call that connects to nothing and then settle, so the customer
# pays for a call that could never have happened.
#
# The lab's "carrier" is the SIPp UAS on 5070 that answers later in this
# script.
curl -s -m 5 "${OP[@]}" -H "Idempotency-Key: auth-trunk-$$" \
    -d '{"name":"lab-carrier","direction":"OUTBOUND","host":"127.0.0.1",
         "port":5070,"remote_ips":["127.0.0.1"],"transport":"UDP"}' \
    "$PROV/v1/trunks" > /dev/null

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

# NO MANUAL RELOAD HERE, DELIBERATELY.
#
# db_text caches its tables at load, so somebody has to tell the switch. This
# script used to do it with a curl — which meant the test passed whether or
# not the SERVICE did, and it did not. Provisioning owns that call now
# (SwitchReloader), and leaving it out here is what lets registration below
# fail if the service ever stops making it.
#
# Give the export thread a moment to write and reload.
sleep 3

step "3. the softphone registers"

printf 'SEQUENTIAL\n%s;labdialer;labdialer\n' "$REALM" > /tmp/lab-reg.csv
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

step "6. the same call again, this time carrying audio"

# THE OTHER HALF OF THE MEDIA CHECK.
#
# The call above was billed with NO-MEDIA set, correctly -- it sent no RTP.
# This one must be billed with the bytes counted and the flag clear. A switch
# that cannot tell the two apart bills silence at the full rate, which is one
# of the three money-losing failure modes.
#
# sudo, because play_pcap_audio opens a raw socket. Without it SIPp reports
# success and sends nothing, which is indistinguishable from the silent
# scenario -- the test would pass while measuring the wrong thing.
timeout 60 sipp -sn uas -p 5070 -m 1 -bg > /dev/null 2>&1
sleep 1

before_audio=$(balance)
printf 'SEQUENTIAL\n%s;labdialer;12125551234\n' "$REALM" > /tmp/lab-audio.csv
sudo timeout 60 sipp -sf "$HERE/sipp-call-authenticated-audio.xml" 127.0.0.1:5060 \
    -inf /tmp/lab-audio.csv -au labdialer -ap "$PASSWORD" \
    -m 1 -r 1 -timeout 40 -trace_err -error_file /tmp/lab-audio.err \
    > /tmp/lab-audio.log 2>&1
rc=$?
pkill -f 'sipp -sn uas' 2>/dev/null
[ $rc -eq 0 ] || { sed -n '1,15p' /tmp/lab-audio.err 2>/dev/null; fatal "the audio call failed"; }

sleep 2
after_audio=$(balance)
[ "$after_audio" != "$before_audio" ] || fatal "the audio call was not billed"

CDR=$(grep '^CDR' /tmp/switch.log | tail -1)
echo "$CDR"

echo "$CDR" | grep -q 'NO-MEDIA' \
    && fatal "a call that carried G.711 was flagged NO-MEDIA -- the flag is meaningless"

# media=0 would mean the flag is clear only because the stats were unreadable,
# which is the same blind spot wearing a different hat.
echo "$CDR" | grep -qE 'media=[1-9][0-9]*' \
    || fatal "no media bytes counted on a call that sent G.711: $CDR"
echo "audio counted, NO-MEDIA correctly absent"

step "7. it was billed to who they PROVED they are"

# The whole reason authentication is on the call path. If the switch had used
# the From header, this would still pass -- they match here -- so the negative
# case lives in register-test.sh, where From is deliberately somebody else.
sudo journalctl -t opensips --since '-1 min' | grep -q 'allow labdialer' \
    || fatal "the switch did not authorize labdialer by its authenticated identity"
echo "authorized as labdialer"

echo
echo "=== the whole business ran: login, call, bill ==="
sudo journalctl -t opensips --since '-1 min' | grep MEGATRON | tail -8
