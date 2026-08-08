#!/bin/bash
#
# MEGATRON lab — does a softphone actually log in, and do forgeries fail?
#
# Four cases, run against a live OpenSIPS with the auth config:
#
#   1  correct password                      -> 200, and a binding exists
#   2  wrong password                        -> 403
#   3  unknown account                       -> 403
#   4  valid login, someone else's From      -> 403
#
# Case 4 is the one worth the whole file. Cases 2 and 3 are the attacks
# everyone expects and every switch stops. Case 4 is a caller who authenticates
# perfectly and then bills a different account -- every credential valid, no
# protocol violation anywhere, and it is the shape of the attacks that keep
# hitting MagnusBilling installs.
#
# Usage:  bash register-test.sh [realm]

set -u

REALM=${1:-sip.megatron.local}
HOST=127.0.0.1:5060
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

pass=0
fail=0

# SIPp's injection files are semicolon-separated with a header line naming the
# separator. One file per case: SIPp reads them sequentially, so sharing one
# file across runs would hand the second case the first case's row.
inject() {
    local file=$1; shift
    { echo "SEQUENTIAL"; local IFS=';'; echo "$*"; } > "$file"
}

# SIPp hangs forever on its curses UI when a scenario does not complete, so
# every run is wrapped in timeout. -m 1 stops after one call; -timeout bounds
# the call itself. Without both, a failing case blocks the suite rather than
# failing it.
run() {
    local name=$1 scenario=$2 realm=$3 authuser=$4 password=$5 fromuser=$6
    local inf="$WORK/$name.csv"
    inject "$inf" "$realm" "$fromuser"

    # -au/-ap rather than injection fields: SIPp substitutes [fieldN] before
    # it parses keywords, so [authentication username=[field1]] does not nest.
    # It emits the field value followed by the literal keyword text and takes
    # the username from uninitialised memory -- a message that looks almost
    # right and authenticates as garbage.
    if timeout 25 sipp -sf "$HERE/$scenario" "$HOST" \
            -inf "$inf" -au "$authuser" -ap "$password" \
            -m 1 -r 1 -timeout 10 -trace_err -trace_msg \
            -error_file "$WORK/$name.err" -message_file "$WORK/$name.msg" \
            > "$WORK/$name.log" 2>&1; then
        echo "  PASS  $name"
        pass=$((pass + 1))
    else
        echo "  FAIL  $name"
        # The error file is empty when SIPp simply timed out, which is the
        # most common way this fails; fall back to the last messages actually
        # exchanged, because "nothing happened" and "the wrong thing happened"
        # need completely different fixes.
        if [ -s "$WORK/$name.err" ]; then
            sed -n '1,10p' "$WORK/$name.err" | sed 's/^/        /'
        else
            echo "        (no SIPp error; last messages exchanged:)"
            grep -E '^(UDP message|REGISTER|SIP/2.0)' "$WORK/$name.msg" 2>/dev/null \
                | tail -6 | sed 's/^/        /'
        fi
        fail=$((fail + 1))
    fi
}

echo "MEGATRON registration tests against $HOST (realm $REALM)"
echo

# The password must match the HA1 in /etc/opensips/dbtext/subscriber.
PASSWORD=${MEGATRON_LAB_PASSWORD:-labpassword}

echo "1. a customer logs in with the right password"
run correct        sipp-register.xml        "$REALM" bigcorp "$PASSWORD" bigcorp

echo "2. the same customer with the wrong password"
run wrong-password sipp-register-denied.xml "$REALM" bigcorp "not-the-password" bigcorp

echo "3. an account that does not exist"
run unknown-user   sipp-register-denied.xml "$REALM" ghost   "$PASSWORD" ghost

echo "4. a valid login claiming somebody else's account in From"
run from-spoof     sipp-register-denied.xml "$REALM" bigcorp "$PASSWORD" victim

echo
echo "5. a wrong password and an unknown account are indistinguishable"
# THE ENUMERATION CHECK.
#
# If a wrong password is refused differently from an unknown handle, an
# attacker sends any password at a guessed name and reads the reply to learn
# whether the account is real -- one packet per guess, no credential needed,
# and it is what turns an untargeted scan into a targeted brute force. The
# operator still needs to know which happened, so the distinction lives in the
# log, where an attacker cannot read it. That is checked separately below.
final_status() {
    grep -E '^SIP/2\.0 [0-9]{3}' "$WORK/$1.msg" 2>/dev/null | tail -1 | tr -d '\r'
}
A=$(final_status wrong-password)
B=$(final_status unknown-user)
if [ -n "$A" ] && [ "$A" = "$B" ]; then
    echo "  PASS  both answered '$A'"
    pass=$((pass + 1))
else
    echo "  FAIL  wrong password -> '$A', unknown account -> '$B'"
    echo "        the difference tells an attacker which handles are real"
    fail=$((fail + 1))
fi

echo
echo "5b. but the operator can still tell them apart, in the log"
if sudo journalctl -t opensips --since '-2 min' 2>/dev/null | grep -q 'AUTH DENIED'; then
    echo "  PASS  the denial was logged"
    pass=$((pass + 1))
else
    echo "  FAIL  a uniform response AND no log entry is just a blind spot"
    fail=$((fail + 1))
fi

echo
echo "6. the binding actually exists (a 200 that registered nothing is a lie)"
LOCATION=$(curl -s --max-time 5 http://127.0.0.1:8888/mi \
           -H 'Content-Type: application/json' \
           -d '{"jsonrpc":"2.0","id":1,"method":"ul_dump"}' 2>/dev/null)
if echo "$LOCATION" | grep -q bigcorp; then
    echo "  PASS  bigcorp has a location binding"
    pass=$((pass + 1))
else
    echo "  FAIL  no binding for bigcorp (dump: $(echo "$LOCATION" | head -c 200))"
    fail=$((fail + 1))
fi

echo
echo "7. the switch logged the spoof attempt (a silent refusal teaches nobody)"
if sudo journalctl -t opensips --since '-2 min' 2>/dev/null | grep -q 'IDENTITY MISMATCH'; then
    echo "  PASS  the identity mismatch was logged"
    pass=$((pass + 1))
else
    echo "  FAIL  nothing in the log about the spoof attempt"
    fail=$((fail + 1))
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
