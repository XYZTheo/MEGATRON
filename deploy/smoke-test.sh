#!/bin/bash
#
# MEGATRON — did the install actually work?
#
#   sudo bash deploy/smoke-test.sh
#
# Creates a throwaway carrier, plan, rate and customer, registers a softphone
# against the REAL switch, places a call, and checks the balance moved by
# exactly what the rate says. Then removes what it created.
#
# WHY THIS EXISTS SEPARATELY FROM install.sh's CHECKS. Those confirm each
# process is up and listening. Up is not the same as working: a switch can be
# running, answering, and refusing every call — or worse, carrying them and
# billing nothing. The only question that matters is whether a call gets
# authorized, connected, and charged, and the only way to answer it is to make
# one.
#
# It uses the same SIPp scenarios as lab/, because a second set of scenarios
# would be a second thing to keep true.

set -u

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ENV_FILE=/etc/megatron/megatron.env
SECRETS=/etc/megatron/secrets.env
PROV=http://127.0.0.1:8081

step()  { echo; echo "==> $*"; }
fatal() { echo "FAILED: $*" >&2; cleanup; exit 1; }

[ "$(id -u)" -eq 0 ] || fatal "run this with sudo (it reads $SECRETS)"
[ -r "$SECRETS" ] || fatal "$SECRETS is not readable — is MEGATRON installed?"

# shellcheck disable=SC1090
. "$ENV_FILE"
TOKEN=$(grep '^MEGATRON_OPERATOR_TOKEN=' "$SECRETS" | cut -d= -f2-)
[ -n "$TOKEN" ] || fatal "no operator token in $SECRETS"
REALM=${MEGATRON_SIP_REALM:-sip.megatron.local}

OP=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")
STAMP=$$
HANDLE="smoke$STAMP"
jget() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)" 2>/dev/null; }

cleanup() {
    pkill -f 'sipp -sn uas' 2>/dev/null
    # The customer is suspended rather than deleted: this codebase has no
    # delete, deliberately — an append-only audit trail is not one you can
    # tidy. Suspending removes them from the credential file, which is the
    # property that matters.
    if [ -n "${CUST_ID:-}" ]; then
        curl -s -m 5 "${OP[@]}" -H "Idempotency-Key: smoke-off-$STAMP" \
            -X POST -d '{"status":"SUSPENDED","reason":"smoke test finished"}' \
            "$PROV/v1/customers/$CUST_ID/status" > /dev/null 2>&1
    fi
}
trap cleanup EXIT

command -v sipp >/dev/null || fatal "sipp is not installed: apt-get install -y sip-tester"

step "1/5  a carrier, a plan, a rate, a customer"

# The "carrier" is a SIPp UAS this script starts on 5070. It answers, so the
# call completes and can be billed — which is the whole point.
TRUNK=$(curl -s -m 5 "${OP[@]}" -H "Idempotency-Key: smoke-trunk-$STAMP" \
    -d '{"name":"smoke-carrier","direction":"outbound","host":"127.0.0.1",
         "port":5070,"remote_ips":["127.0.0.1"],"transport":"udp"}' \
    "$PROV/v1/trunks")
echo "$TRUNK" | grep -q '"id"' || fatal "no carrier could be created: $TRUNK"

PLAN=$(curl -s -m 5 "${OP[@]}" -H "Idempotency-Key: smoke-plan-$STAMP" \
    -d '{"name":"Smoke","currency":"USD"}' "$PROV/v1/plans" | jget 'd["id"]')
[ -n "$PLAN" ] || fatal "no plan could be created"

# 1 cent a minute, 60-second increments: any answered call under a minute
# costs exactly 10000 micro-units, which is checkable by hand.
curl -s -m 5 "${OP[@]}" -H "Idempotency-Key: smoke-rates-$STAMP" -X PUT \
    -d '{"rates":[{"prefix":"1","description":"US","sell_micros_per_minute":10000,
         "connect_fee_micros":0,"increment_seconds":60,"minimum_seconds":0}]}' \
    "$PROV/v1/plans/$PLAN/rates" > /dev/null

CUST=$(curl -s -m 5 "${OP[@]}" -H "Idempotency-Key: smoke-cust-$STAMP" \
    -d "{\"handle\":\"$HANDLE\",\"plan_id\":\"$PLAN\",\"opening_balance_micros\":5000000}" \
    "$PROV/v1/customers")
CUST_ID=$(echo "$CUST" | jget 'd["customer"]["id"]')
PASSWORD=$(echo "$CUST" | jget 'd["credentials"]["sip_password"]')
[ -n "$PASSWORD" ] || fatal "no customer could be created: $CUST"
echo "customer $HANDLE, balance 5000000u"

step "2/5  the credential reaches the switch"

# Waiting for PROVISIONING to export and reload it. Doing either here would
# make this test pass whether or not the service does its job.
for _ in $(seq 1 40); do
    grep -q "^$HANDLE:" "${MEGATRON_SUBSCRIBER_FILE:-/etc/opensips/dbtext/subscriber}" 2>/dev/null && break
    sleep 1
done
grep -q "^$HANDLE:" "${MEGATRON_SUBSCRIBER_FILE:-/etc/opensips/dbtext/subscriber}" 2>/dev/null \
    || fatal "provisioning never exported the credential"
sleep 2   # let the reload land
echo "exported and reloaded"

step "3/5  a softphone registers"

printf 'SEQUENTIAL\n%s;%s;%s\n' "$REALM" "$HANDLE" "$HANDLE" > /tmp/smoke-reg.csv
timeout 30 sipp -sf "$REPO/lab/sipp-register.xml" 127.0.0.1:5060 \
    -inf /tmp/smoke-reg.csv -au "$HANDLE" -ap "$PASSWORD" \
    -m 1 -r 1 -timeout 15 -trace_err -error_file /tmp/smoke-reg.err > /dev/null 2>&1 \
    || { sed -n '1,12p' /tmp/smoke-reg.err 2>/dev/null; fatal "the softphone could not register"; }
echo "registered"

balance() {
    curl -s -m 5 "${OP[@]}" "$PROV/v1/customers/$CUST_ID" | jget 'd["balance_micros"]'
}
BEFORE=$(balance)

step "4/5  a call"

# -bg makes SIPp background ITSELF, so this shell never has a job for it and
# $! is unset — which under `set -u` aborts the script at the most confusing
# possible moment, right after everything interesting has already worked.
# cleanup() finds it by name instead.
timeout 60 sipp -sn uas -p 5070 -m 1 -bg > /dev/null 2>&1
sleep 1

printf 'SEQUENTIAL\n%s;%s;12125551234\n' "$REALM" "$HANDLE" > /tmp/smoke-call.csv
timeout 60 sipp -sf "$REPO/lab/sipp-call-authenticated.xml" 127.0.0.1:5060 \
    -inf /tmp/smoke-call.csv -au "$HANDLE" -ap "$PASSWORD" \
    -m 1 -r 1 -timeout 40 -trace_err -error_file /tmp/smoke-call.err \
    > /dev/null 2>&1
rc=$?
pkill -f 'sipp -sn uas' 2>/dev/null
[ $rc -eq 0 ] || {
    sed -n '1,15p' /tmp/smoke-call.err 2>/dev/null
    journalctl -u megatron-opensips --since '-2 min' 2>/dev/null | grep MEGATRON | tail -10
    fatal "the call did not complete"
}
echo "call completed"

step "5/5  the balance moved by exactly the rate"

sleep 2
AFTER=$(balance)
SPENT=$((BEFORE - AFTER))
echo "balance $BEFORE -> $AFTER  (spent ${SPENT}u)"

[ "$SPENT" -eq 10000 ] \
    || fatal "expected 10000u for one 60-second increment, billed ${SPENT}u"

echo
echo "=== MEGATRON works: a customer logged in, called, and was billed ==="
echo "The smoke-test customer '$HANDLE' has been suspended, not deleted —"
echo "the transaction record is append-only on purpose."
