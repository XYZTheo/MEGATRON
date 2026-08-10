#!/bin/bash
# A CARRIER CALLS ONE OF OUR CUSTOMERS, end to end, on a running MEGATRON.
#
# This is the half of the business an operator sells when he tells a provider
# to point their traffic at this address, and until now nothing exercised it:
# every other lab script has a customer placing a call, never receiving one.
#
# Requires a deployed switch (deploy/install.sh) and sipp.
set -u
API=${MEGATRON_API:-http://127.0.0.1:8081/v1}
DOMAIN=${MEGATRON_SIP_REALM:-privatesip.com}
SWITCH=${MEGATRON_SWITCH:-127.0.0.1:5060}
LAB=$(cd "$(dirname "$0")" && pwd)
STAMP=$(date +%s)
HANDLE="inb$STAMP"
DID="+44163296${STAMP: -4}"
PHONE_PORT=${PHONE_PORT:-5081}
CARRIER_PORT=${CARRIER_PORT:-5082}
# Where the customer's phone actually answers. See step 4 for why this is not
# the same socket the REGISTER goes out from.
ANSWER_PORT=${ANSWER_PORT:-5083}

TOKEN=$(sudo grep '^MEGATRON_OPERATOR_TOKEN=' /etc/megatron/secrets.env | cut -d= -f2-)
A=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")

pass=0; fail=0
check() {
    if [ "$2" = "$3" ]; then
        echo "  ok   $1"; pass=$((pass+1))
    else
        echo "  FAIL $1: expected '$3', got '$2'"; fail=$((fail+1))
    fi
}

UAS_PID=""
cleanup() { [ -n "$UAS_PID" ] && kill "$UAS_PID" 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT

# A RUN THAT DIES LEAVES SIPp HOLDING A PORT, and the next run then fails with
# "Unable to bind main socket" -- which SIPp reports on stderr and which shows
# up here as "the phone did not log in", pointing at the switch instead of at
# the previous run. Clear our own leftovers, then refuse to start if something
# else owns the port rather than guessing.
echo "=== 0. ports ==="
for port in "$PHONE_PORT" "$CARRIER_PORT" "$ANSWER_PORT"; do
    pids=$(sudo ss -lunp 2>/dev/null | awk -v p=":$port" '$5 ~ p {print $0}' \
           | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u)
    for pid in $pids; do
        if ps -p "$pid" -o comm= 2>/dev/null | grep -q sipp; then
            echo "  killing leftover sipp $pid on $port"
            sudo kill "$pid" 2>/dev/null
        else
            echo "  PORT $port IS HELD BY PID $pid ($(ps -p "$pid" -o comm= 2>/dev/null))"
            exit 1
        fi
    done
done
sleep 2
echo "  clear"

echo
echo "=== 1. an inbound trunk for the 'carrier' (this box) ==="
# 127.0.0.1 because the carrier in this test is a SIPp on the same machine.
# A real one is the provider's address, and it is the same field.
TRUNK=$(curl -s -m 10 "${A[@]}" -H "Idempotency-Key: inb-trunk-$STAMP" -d "{
  \"name\":\"lab-carrier-$STAMP\",\"direction\":\"inbound\",
  \"host\":\"127.0.0.1\",\"port\":5060,
  \"remote_ips\":[\"127.0.0.1\"],\"transport\":\"udp\"}" $API/trunks)
echo "$TRUNK" | grep -q '"id"' && echo "  created" || { echo "  TRUNK NOT CREATED: $TRUNK"; exit 1; }

echo
echo "=== 2. a customer with a number ==="
PLAN=$(curl -s -m 10 "${A[@]}" -H "Idempotency-Key: inb-plan-$STAMP" \
  -d "{\"name\":\"Inbound $STAMP\",\"currency\":\"USD\"}" $API/plans \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
curl -s -m 10 "${A[@]}" -H "Idempotency-Key: inb-rates-$STAMP" -X PUT \
  -d '{"rates":[{"prefix":"1","description":"US","sell_micros_per_minute":10000,
       "increment_seconds":60}]}' $API/plans/$PLAN/rates >/dev/null
CUST=$(curl -s -m 10 "${A[@]}" -H "Idempotency-Key: inb-cust-$STAMP" \
  -d "{\"handle\":\"$HANDLE\",\"plan_id\":\"$PLAN\",\"opening_balance_micros\":5000000}" \
  $API/customers)
CID=$(echo "$CUST" | python3 -c 'import sys,json;print(json.load(sys.stdin)["customer"]["id"])')
PW=$(echo "$CUST" | python3 -c 'import sys,json;print(json.load(sys.stdin)["credentials"]["sip_password"])')
[ -n "$CID" ] || { echo "  CUSTOMER NOT CREATED: $CUST"; exit 1; }
DIDRSP=$(curl -s -m 10 "${A[@]}" -H "Idempotency-Key: inb-did-$STAMP" \
  -d "{\"number\":\"$DID\",\"customer_id\":\"$CID\"}" $API/dids)
# STORED WITHOUT THE '+'. normaliseDid() strips it, so a carrier's INVITE --
# whose request URI has no plus either -- matches the row. Checking for the
# string we sent rather than the string that comes back reported a successful
# assignment as a failure.
echo "$DIDRSP" | grep -q "${DID#+}" && echo "  $HANDLE owns $DID" \
    || { echo "  DID NOT ASSIGNED: $DIDRSP"; exit 1; }

echo
echo "=== 3. wait for the credential to reach the switch ==="
for i in $(seq 1 30); do
    sudo grep -q "^$HANDLE:" /etc/opensips/dbtext/subscriber 2>/dev/null && break
    sleep 2
done
sudo grep -q "^$HANDLE:" /etc/opensips/dbtext/subscriber \
    && echo "  exported" || { echo "  NOT EXPORTED"; exit 1; }
sleep 3

echo
echo "=== 4. the customer's phone logs in and waits to be called ==="
# TWO PROCESSES, ONE PHONE. SIPp matches incoming messages to calls by
# Call-ID, so a scenario that registers cannot also answer the INVITE that
# arrives later -- it has a different Call-ID, SIPp starts the scenario afresh
# at its `send REGISTER`, and the caller gets 408. The registration therefore
# advertises the UAS's port as its Contact, and the switch cannot tell.
sipp -sn uas -p "$ANSWER_PORT" -m 1 -timeout 90 \
     -trace_err -error_file /tmp/inb-uas.err > /tmp/inb-uas.out 2>&1 &
UAS_PID=$!
sleep 2

printf 'SEQUENTIAL\n%s;%s;%s\n' "$DOMAIN" "$HANDLE" "$ANSWER_PORT" > /tmp/inb-phone.csv
timeout 30 sipp -sf "$LAB/sipp-register-contact.xml" "$SWITCH" \
     -inf /tmp/inb-phone.csv -au "$HANDLE" -ap "$PW" \
     -p "$PHONE_PORT" -m 1 -r 1 -timeout 20 -trace_err -error_file /tmp/inb-phone.err \
     > /tmp/inb-phone.out 2>&1
check "the phone logged in" "$?" "0"
sleep 2

# The registration is what makes the customer reachable, so it is checked
# BEFORE the call rather than inferred from the call failing.
REG=$(curl -s -m 10 "${A[@]}" $API/customers/$CID/registration \
      | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("registered"))' 2>/dev/null)
check "the phone is registered" "$REG" "True"

echo
echo "=== 5. the carrier calls $DID ==="
printf 'SEQUENTIAL\n%s;%s;%s\n' "$DID" "12125551234" "$DOMAIN" > /tmp/inb-carrier.csv
timeout 60 sipp -sf "$LAB/sipp-carrier-inbound.xml" "$SWITCH" \
     -inf /tmp/inb-carrier.csv -p "$CARRIER_PORT" -m 1 -r 1 -timeout 45 \
     -trace_err -error_file /tmp/inb-carrier.err > /tmp/inb-carrier.out 2>&1
CARRIER_RC=$?
check "the carrier's call completed" "$CARRIER_RC" "0"

wait $UAS_PID 2>/dev/null
PHONE_RC=$?
check "the phone answered it" "$PHONE_RC" "0"

echo
echo "=== 6. is it on the customer's record? ==="
sleep 3
CDR=$(curl -s -m 10 "${A[@]}" "$API/customers/$CID/calls")
echo "$CDR" | python3 -c 'import sys,json
rows=json.load(sys.stdin)
if not rows:
    print("  NO CDR"); raise SystemExit
c=rows[0]
print("  CDR %s %s -> %s  %ss  charged %s micros  source=%s" % (
      c.get("direction"), c.get("account"), c.get("destination"),
      c.get("duration_seconds"), c.get("charged_micros"), c.get("duration_source")))'
DIRECTION=$(echo "$CDR" | python3 -c 'import sys,json
rows=json.load(sys.stdin); print(rows[0].get("direction") if rows else "none")')
check "the record says it was inbound" "$DIRECTION" "inbound"

# The plan prices "1" and nothing else, so a call to a 44 DID is unpriced --
# free, and the balance must be untouched. An inbound call that quietly bills
# the customer at some other prefix's rate is the failure this catches.
BAL=$(curl -s -m 10 "${A[@]}" $API/customers/$CID \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["balance_micros"])')
check "an unpriced inbound call cost nothing" "$BAL" "5000000"

echo
echo "=== 7. a call to a number nobody owns ==="
printf 'SEQUENTIAL\n%s;%s;%s\n' "+441632999999" "12125551234" "$DOMAIN" > /tmp/inb-nodid.csv
timeout 30 sipp -sf "$LAB/sipp-carrier-inbound.xml" "$SWITCH" \
     -inf /tmp/inb-nodid.csv -p $((CARRIER_PORT+1)) -m 1 -r 1 -timeout 20 \
     > /tmp/inb-nodid.out 2>&1
NODID_RC=$?
# Non-zero: the scenario expects a 200 and must not get one.
[ "$NODID_RC" != "0" ] && NODID=refused || NODID=connected
check "an unknown number is refused" "$NODID" "refused"

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" = "0" ]
