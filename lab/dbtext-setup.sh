#!/bin/bash
#
# MEGATRON lab — stand up the db_text credential store OpenSIPS reads.
#
# In production this directory is written by provisioning (SubscriberFile).
# Here it is seeded with one known account so the registration tests have a
# password they can assert against.
#
# Usage:  sudo bash dbtext-setup.sh [handle] [password] [realm]

set -eu

HANDLE=${1:-bigcorp}
PASSWORD=${2:-labpassword}
REALM=${3:-sip.megatron.local}
D=/etc/opensips/dbtext

mkdir -p "$D"

# THE VERSION NUMBER IS NOT COSMETIC AND IS NOT GUESSABLE.
#
# auth_db refuses to start against a table whose declared version does not
# match what the build expects, and the check runs at fixup -- which means
# `opensips -C` reports the config as OK and the switch then fails to start.
# That is worth knowing generally: -C does not exercise this path, so a config
# that validates can still refuse to run.
#
# 8 is what OpenSIPS 3.6.7 expects. If a future build disagrees it says so
# exactly: "invalid version N for table subscriber found, expected M".
cat > "$D/version" <<'EOF'
table_name(str) table_version(int)
subscriber:8
EOF

# HA1 = MD5(username:realm:password) -- the same derivation provisioning does
# in SubscriberExport.kt. Computed here independently so that if the two ever
# disagree, this test is what catches it rather than a customer.
HA1=$(printf '%s' "$HANDLE:$REALM:$PASSWORD" | md5sum | cut -d' ' -f1)

# THREE COLUMNS, NOT FOUR. There is no ha1b column.
#
# db_text validates every declared column on load and rejects a null field, so
# declaring ha1b and leaving it empty does not degrade one login -- it makes
# the whole table fail to parse. auth_db then reports "table 'subscriber' does
# not exist" and every REGISTER gets a 500. An unused column is not free.
#
# The trailing newline matters too: db_text drops an unterminated final line,
# which silently loses whichever account sorts last.
cat > "$D/subscriber" <<EOF
username(str) domain(str) ha1(str)
$HANDLE:$REALM:$HA1
EOF

# The file is a list of password-equivalent credentials.
chmod 640 "$D/subscriber"
chown root:root "$D/subscriber" 2>/dev/null || true

echo "seeded $HANDLE@$REALM in $D/subscriber"
