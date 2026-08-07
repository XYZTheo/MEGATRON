#!/usr/bin/env bash
# ONE CALL WITH REAL AUDIO: SIPp sends RTP, rtpengine anchors it, the switch
# bills it and reports how many bytes actually flowed.
set -uo pipefail
cd ~/megatron

export MEGATRON_DB_URL="jdbc:sqlite:/home/ubuntu/megatron.db"
export MEGATRON_OPERATOR_TOKEN="lab-operator-token-at-least-32-chars-long"
OP=(-H "Authorization: Bearer $MEGATRON_OPERATOR_TOKEN" -H "Content-Type: application/json")

sudo pkill -9 opensips 2>/dev/null; sudo pkill -9 sipp 2>/dev/null
pkill -9 -f 'build/install' 2>/dev/null; sudo pkill -9 rtpengine 2>/dev/null
sleep 2
rm -f /home/ubuntu/megatron.db* /tmp/switch.log /tmp/uac.err
mkdir -p /tmp/lab_fifo

echo "=== build ==="
./gradlew :provisioning:installDist :switch-api:installDist --console=plain --no-daemon -q 2>&1 | tail -3

echo "=== rtpengine ==="
sudo rtpengine --interface=127.0.0.1 --listen-ng=127.0.0.1:22222 \
  --port-min=30000 --port-max=30200 --foreground --log-level=5 \
  --pidfile=/tmp/rtpengine.pid > /tmp/rtpengine.log 2>&1 &
sleep 3
pgrep -x rtpengine >/dev/null && echo "  rtpengine up" || { echo "  RTPENGINE FAILED"; tail -12 /tmp/rtpengine.log; }

echo "=== services ==="
MEGATRON_PROVISIONING_PORT=8081 nohup provisioning/build/install/provisioning/bin/provisioning >/tmp/prov.log 2>&1 &
MEGATRON_SWITCH_API_PORT=8082 nohup switch-api/build/install/switch-api/bin/switch-api >/tmp/switch.log 2>&1 &
for i in $(seq 1 40); do
  p=$(curl -s -m 2 -o /dev/null -w '%{http_code}' "${OP[@]}" http://127.0.0.1:8081/v1/customers 2>/dev/null)
  s=$(curl -s -m 2 -o /dev/null -w '%{http_code}' http://127.0.0.1:8082/v1/health 2>/dev/null)
  [ "$p" = "200" ] && [ "$s" = "200" ] && break; sleep 2
done
echo "  provisioning=$p switch-api=$s"

PLAN=$(curl -s -m 5 "${OP[@]}" -H 'Idempotency-Key: rtp-plan-001' -d '{"name":"Retail","currency":"USD"}' http://127.0.0.1:8081/v1/plans | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
curl -s -m 5 "${OP[@]}" -H 'Idempotency-Key: rtp-rates-001' -X PUT -d '{"rates":[{"prefix":"1","sell_micros_per_minute":60000,"increment_seconds":1}]}' "http://127.0.0.1:8081/v1/plans/$PLAN/rates" >/dev/null
curl -s -m 5 "${OP[@]}" -H 'Idempotency-Key: rtp-cust-001' -d "{\"handle\":\"bigcorp\",\"plan_id\":\"$PLAN\",\"opening_balance_micros\":25000000}" http://127.0.0.1:8081/v1/customers >/dev/null
echo "  seeded"

echo "=== OpenSIPS (with rtpengine) ==="
opensips -C -f /tmp/lab2.cfg 2>&1 | grep -E 'ERROR|CRITICAL' | head -5
sudo opensips -f /tmp/lab2.cfg -P /tmp/lab.pid >/tmp/opensips.out 2>&1
sleep 3
pgrep -x opensips >/dev/null && echo "  opensips up" || { echo "  DID NOT START"; head -15 /tmp/opensips.out; }

echo "=== carrier: SIPp UAS echoing RTP on 5070 ==="
sudo nohup sipp -sn uas -p 5070 -i 127.0.0.1 -m 1 -rtp_echo >/tmp/uas.log 2>&1 &
sleep 3
pgrep -x sipp >/dev/null && echo "  UAS up" || echo "  UAS FAILED"

echo
echo "=== THE CALL, WITH AUDIO ==="
ls -la /usr/share/sip-tester/g711a.pcap
sudo timeout 60 sipp -sf /tmp/uac2.xml -s 12125551234 127.0.0.1:5060 \
  -i 127.0.0.1 -p 5080 -m 1 -r 1 -timeout 40 -trace_err -error_file /tmp/uac.err \
  >/tmp/uac.log 2>&1
echo "  sipp exit: $?"
grep -E 'Successful call|Failed call' /tmp/uac.log | head -2

sleep 3

echo
echo "=== THE SECOND CALL: SIGNALLING ONLY, NO AUDIO AT ALL ==="
echo "    (the failure mode that bills a customer for silence)"
sudo timeout 60 sipp -sf /tmp/uac.xml -s 12125551234 127.0.0.1:5060 \
  -i 127.0.0.1 -p 5081 -m 1 -r 1 -timeout 40 -trace_err -error_file /tmp/uac2.err \
  >/tmp/uac_silent.log 2>&1
echo "  sipp exit: $?"
grep -E 'Successful call' /tmp/uac_silent.log | head -1

sleep 3
echo
echo "=== OpenSIPS ==="
sudo journalctl -t opensips --no-pager -n 300 2>/dev/null | grep MEGATRON | sed 's/.*MEGATRON/MEGATRON/' | tail -10

echo
echo "=== rtpengine saw ==="
sudo journalctl -t rtpengine --no-pager --since '-3min' 2>/dev/null | tail -8
grep -iE 'Final|bytes|command' /tmp/rtpengine.log | tail -6

echo
echo "=== CDR ==="
grep '^CDR' /tmp/switch.log | tail -2

echo
echo "=== balance ==="
curl -s -m 5 "${OP[@]}" http://127.0.0.1:8081/v1/customers | python3 -c 'import sys,json;c=json.load(sys.stdin)["items"][0];print("  ",c["balance_micros"],"micros")' 2>/dev/null || echo "  (query failed)"

sudo pkill -9 opensips; sudo pkill -9 sipp; pkill -9 -f 'build/install'; sudo pkill -9 rtpengine
echo "=== done ==="
