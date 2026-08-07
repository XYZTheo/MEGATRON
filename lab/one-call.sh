#!/usr/bin/env bash
# ONE CALL, END TO END. Everything is bounded by `timeout` so nothing can hang.
set -uo pipefail
cd ~/megatron

export MEGATRON_DB_URL="jdbc:sqlite:/home/ubuntu/megatron.db"
export MEGATRON_OPERATOR_TOKEN="lab-operator-token-at-least-32-chars-long"
OP=(-H "Authorization: Bearer $MEGATRON_OPERATOR_TOKEN" -H "Content-Type: application/json")

echo "=== clean slate ==="
sudo pkill -9 opensips 2>/dev/null; pkill -9 sipp 2>/dev/null
pkill -9 -f 'build/install' 2>/dev/null
sleep 2
rm -f /home/ubuntu/megatron.db*
mkdir -p /tmp/lab_fifo
sudo truncate -s 0 /var/log/syslog 2>/dev/null || true

echo "=== build ==="
./gradlew :provisioning:installDist :switch-api:installDist --console=plain --no-daemon -q 2>&1 | tail -3

echo "=== services ==="
MEGATRON_PROVISIONING_PORT=8081 nohup provisioning/build/install/provisioning/bin/provisioning >/tmp/prov.log 2>&1 &
MEGATRON_SWITCH_API_PORT=8082 nohup switch-api/build/install/switch-api/bin/switch-api >/tmp/switch.log 2>&1 &
for i in $(seq 1 40); do
  p=$(curl -s -m 2 -o /dev/null -w '%{http_code}' "${OP[@]}" http://127.0.0.1:8081/v1/customers 2>/dev/null)
  s=$(curl -s -m 2 -o /dev/null -w '%{http_code}' http://127.0.0.1:8082/v1/health 2>/dev/null)
  [ "$p" = "200" ] && [ "$s" = "200" ] && break; sleep 2
done
echo "  provisioning=$p switch-api=$s"

PLAN=$(curl -s -m 5 "${OP[@]}" -H 'Idempotency-Key: call-plan-001' -d '{"name":"Retail","currency":"USD"}' http://127.0.0.1:8081/v1/plans | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
curl -s -m 5 "${OP[@]}" -H 'Idempotency-Key: call-rates-001' -X PUT -d '{"rates":[{"prefix":"1","sell_micros_per_minute":60000,"increment_seconds":1}]}' "http://127.0.0.1:8081/v1/plans/$PLAN/rates" >/dev/null
curl -s -m 5 "${OP[@]}" -H 'Idempotency-Key: call-cust-001' -d "{\"handle\":\"bigcorp\",\"plan_id\":\"$PLAN\",\"opening_balance_micros\":25000000}" http://127.0.0.1:8081/v1/customers | python3 -c 'import sys,json;d=json.load(sys.stdin);print("  customer:",d["customer"]["handle"],d["customer"]["balance_micros"],"micros")'

echo
echo "=== OpenSIPS ==="
sudo opensips -f /tmp/lab.cfg -P /tmp/lab.pid >/tmp/opensips.out 2>&1
sleep 3
if pgrep -x opensips >/dev/null; then echo "  opensips running: $(pgrep -c -x opensips) processes"; else echo "  OPENSIPS DID NOT START"; head -20 /tmp/opensips.out; fi

echo
echo "=== carrier: SIPp UAS on 5070 ==="
nohup sipp -sn uas -p 5070 -i 127.0.0.1 -m 1 >/tmp/uas.log 2>&1 &
sleep 3
pgrep -x sipp >/dev/null && echo "  UAS up" || { echo "  UAS FAILED"; head -10 /tmp/uas.log; }
sleep 2

echo
echo "=== THE CALL ==="
timeout 45 sipp -sf /tmp/uac.xml -s 12125551234 127.0.0.1:5060 \
  -i 127.0.0.1 -p 5080 -m 1 -r 1 -timeout 25 -trace_err -error_file /tmp/uac.err \
  >/tmp/uac.log 2>&1
rc=$?
echo "  sipp exit: $rc  (0 = call completed successfully)"
grep -E 'Successful|Failed|Unexpected' /tmp/uac.log | head -6

echo
echo "=== OpenSIPS decisions ==="
sudo journalctl -t opensips --no-pager -n 200 2>/dev/null | grep MEGATRON | sed "s/.*MEGATRON/MEGATRON/" | tail -8 || sudo grep MEGATRON /var/log/syslog | tail -8

echo
echo "=== CDR ==="
grep '^CDR' /tmp/switch.log | tail -3 || echo "  (none)"

echo
echo "=== balance after ==="
BAL=$(curl -s -m 5 "${OP[@]}" http://127.0.0.1:8081/v1/customers)
echo "  raw: ${BAL:0:160}"

echo
echo "=== errors, if any ==="
[ -s /tmp/uac.err ] && head -12 /tmp/uac.err || echo "  none"

sudo pkill -9 opensips 2>/dev/null; pkill -9 sipp 2>/dev/null; pkill -9 -f 'build/install' 2>/dev/null
echo "=== done ==="
