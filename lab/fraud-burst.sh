#!/bin/bash
# A COMPROMISED LOGIN, against a running MEGATRON.
#
# Dials continuously from one account, the way a stolen SIP credential is
# monetised: short calls, one after another, never enough of them at once to
# reach the concurrency cap. Before the velocity guard existed every one of
# these was authorized, and the only limit was the balance.
#
# What it proves is narrow: the guard fires on the real service, the refusal
# reaches the caller as a plain 403, and the reason is in the operator's log
# and nowhere else.
set -u
API=${MEGATRON_API:-http://127.0.0.1:8081/v1}
AUTHZ=${MEGATRON_AUTHZ:-http://127.0.0.1:8082/v1}
STAMP=$(date +%s)
HANDLE="brst$STAMP"
# One over the default call limit, so the last one must be refused.
BURST=${BURST:-61}

TOKEN=$(sudo grep '^MEGATRON_OPERATOR_TOKEN=' /etc/megatron/secrets.env | cut -d= -f2-)
A=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")

pass=0; fail=0
check() {
    if [ "$2" = "$3" ]; then echo "  ok   $1"; pass=$((pass+1))
    else echo "  FAIL $1: expected '$3', got '$2'"; fail=$((fail+1)); fi
}

echo "=== a customer with plenty of money and a high concurrency cap ==="
PLAN=$(curl -s -m 10 "${A[@]}" -H "Idempotency-Key: brst-plan-$STAMP" \
  -d "{\"name\":\"Burst $STAMP\",\"currency\":\"USD\"}" $API/plans \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
curl -s -m 10 "${A[@]}" -H "Idempotency-Key: brst-rates-$STAMP" -X PUT \
  -d '{"rates":[{"prefix":"1","description":"US","sell_micros_per_minute":6000,
       "increment_seconds":1}]}' $API/plans/$PLAN/rates >/dev/null
CUST=$(curl -s -m 10 "${A[@]}" -H "Idempotency-Key: brst-cust-$STAMP" \
  -d "{\"handle\":\"$HANDLE\",\"plan_id\":\"$PLAN\",
       \"opening_balance_micros\":500000000,\"max_concurrent_calls\":100}" $API/customers)
CID=$(echo "$CUST" | python3 -c 'import sys,json;print(json.load(sys.stdin)["customer"]["id"])')
[ -n "$CID" ] || { echo "  CUSTOMER NOT CREATED: $CUST"; exit 1; }
echo "  $HANDLE, 500.00 balance, 100 concurrent allowed"

echo
echo "=== dialling $BURST times in a row ==="
allowed=0; refused=0; first_refusal=""
for i in $(seq 1 $BURST); do
    RSP=$(curl -s -m 5 -H 'Content-Type: application/json' \
      -d "{\"account\":\"$HANDLE\",\"destination\":\"1212555$(printf %04d $i)\",
           \"call_id\":\"brst-$STAMP-$i\"}" $AUTHZ/authorize)
    D=$(echo "$RSP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("decision"))')
    if [ "$D" = "allow" ]; then
        allowed=$((allowed+1))
        # End it immediately: nothing is ever concurrent, which is the point.
        curl -s -m 5 -H 'Content-Type: application/json' \
          -d "{\"call_id\":\"brst-$STAMP-$i\",\"duration_seconds\":1}" \
          $AUTHZ/session/end >/dev/null
    else
        refused=$((refused+1))
        [ -z "$first_refusal" ] && first_refusal="$RSP"
    fi
done
echo "  allowed $allowed, refused $refused"
[ "$refused" -gt 0 ] && ANY=yes || ANY=no
check "the burst was stopped" "$ANY" "yes"

echo
echo "=== what the caller is told ==="
echo "$first_refusal" | python3 -c 'import sys,json
d=json.load(sys.stdin)
print("  reason: %s  sip_code: %s" % (d.get("reason"), d.get("sip_code")))
print("  detail: %s" % d.get("detail"))'
CODE=$(echo "$first_refusal" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("sip_code"))')
REASON=$(echo "$first_refusal" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("reason"))')
check "the reason is a velocity trip" "$REASON" "fraud_velocity"
# The alert must name the handle, not the internal id: an operator reading
# "cust-1786398571251-4c73" has to go and look it up before they can act.
echo "$first_refusal" | grep -q "$HANDLE" && NAMED=yes || NAMED=no
check "the alert names the customer" "$NAMED" "yes"
# 403 is what a suspended account gets too. A distinct code would tell whoever
# holds the credential exactly what rate to stay under.
check "the wire answer is a bare 403" "$CODE" "403"

echo
echo "=== the money ==="
BAL=$(curl -s -m 10 "${A[@]}" $API/customers/$CID \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["balance_micros"])')
# Every allowed call ran 1s at 6000/min = 100 micros. Refused calls must have
# cost nothing and, crucially, must hold nothing.
EXPECTED=$((500000000 - allowed * 100))
check "only the allowed calls were charged" "$BAL" "$EXPECTED"

echo
echo "=== the operator's log ==="
sudo journalctl -u megatron-switch-api --since -3min 2>/dev/null \
  | grep -a "FRAUD GUARD" | tail -3 | sed 's/^/  /'
LOGGED=$(sudo journalctl -u megatron-switch-api --since -3min 2>/dev/null \
         | grep -ac "FRAUD GUARD" || true)
[ "${LOGGED:-0}" -gt 0 ] && SEEN=yes || SEEN=no
check "the operator can see why" "$SEEN" "yes"

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" = "0" ]
