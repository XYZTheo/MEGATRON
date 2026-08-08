#!/bin/bash
#
# MEGATRON — single-box install.
#
# One command turns a fresh Ubuntu box into a working switch: trunk in, rate,
# authenticate, trunk out, bill. It is the deployment Seth runs on his own
# traffic first (docs/PRODUCT.md), and the thing a licensee runs later.
#
#   sudo bash deploy/install.sh --domain sip.example.com
#
# WHAT IT REFUSES TO DO
#
# There is no path through this script that produces an insecure install.
# Every credential is GENERATED — there is no default password to leave in
# place, which is the defect class that produced MagnusBilling's root/magnus.
# The API tokens land in a mode-0600 file owned by root and are never printed,
# never logged, and never written to the repo.
#
# It is idempotent: run it again after an upgrade and it rebuilds, re-renders
# the config, and restarts, without regenerating secrets or touching the
# database.

set -euo pipefail

DOMAIN=""
PUBLIC_IP=""
SKIP_BUILD=0

usage() {
    cat <<'EOF'
Usage: sudo bash deploy/install.sh --domain <sip domain> [options]

  --domain <fqdn>     The SIP realm customers register against. REQUIRED, and
                      baked into every credential -- changing it later
                      invalidates every password, so pick the one you will
                      actually publish.
  --public-ip <addr>  The address the switch advertises. Detected if omitted.
  --skip-build        Use the jars already under */build/install.

EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --domain)     DOMAIN="${2:-}"; shift 2 ;;
        --public-ip)  PUBLIC_IP="${2:-}"; shift 2 ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage; exit 2 ;;
    esac
done

step()  { echo; echo "==> $*"; }
fatal() { echo "FAILED: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fatal "run this with sudo"
[ -n "$DOMAIN" ] || { usage; fatal "--domain is required"; }

# The realm is baked into every HA1. A typo here is not cosmetic: it is a
# switch nobody can register against, discovered one customer at a time.
case "$DOMAIN" in
    *[!a-zA-Z0-9.-]*|-*|*-|.*|*.) fatal "'$DOMAIN' is not a valid domain" ;;
    *.*) ;;
    *) fatal "'$DOMAIN' does not look like a domain (no dot)" ;;
esac

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ETC=/etc/megatron
VAR=/var/lib/megatron
SECRETS=$ETC/secrets.env
DBTEXT=/etc/opensips/dbtext

step "1/9  preflight"

. /etc/os-release 2>/dev/null || fatal "cannot identify this OS"
[ "${ID:-}" = "ubuntu" ] || [ "${ID:-}" = "debian" ] \
    || fatal "this installer supports Ubuntu and Debian; found '${ID:-unknown}'"

if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
fi
[ -n "$PUBLIC_IP" ] || fatal "could not detect a public IP; pass --public-ip"
echo "domain    $DOMAIN"
echo "public ip $PUBLIC_IP"

# THE PACKAGED opensips.service MUST NOT RUN.
#
# Ubuntu ships it enabled, on the stock config, bound to 127.0.0.1:5060. A
# more specific bind beats a wildcard, so our switch starts cleanly on
# 0.0.0.0:5060, reports exactly that, and receives NONE of the loopback
# traffic -- the stock proxy answers instead, with "476 Unresolvable
# destination". That cost a day in the lab. Masked, not merely stopped, so it
# cannot come back on the next reboot or package upgrade.
if systemctl list-unit-files opensips.service >/dev/null 2>&1; then
    systemctl stop opensips 2>/dev/null || true
    systemctl mask opensips 2>/dev/null || true
    echo "masked the packaged opensips.service"
fi

step "2/9  packages"

export DEBIAN_FRONTEND=noninteractive
if ! grep -rq 'apt.opensips.org' /etc/apt/sources.list.d/ 2>/dev/null; then
    apt-get install -y -qq curl gnupg ca-certificates >/dev/null
    curl -fsSL https://apt.opensips.org/opensips-org.gpg \
        -o /usr/share/keyrings/opensips-org.gpg
    echo "deb [signed-by=/usr/share/keyrings/opensips-org.gpg] " \
         "https://apt.opensips.org ${VERSION_CODENAME} 3.6-releases" \
        | tr -s ' ' > /etc/apt/sources.list.d/opensips.list
    apt-get update -qq
fi

# opensips-auth-modules is easy to miss and its absence looks like a config
# error; opensips-http-modules carries httpd/mi_http, which is how the
# credential reload is delivered.
apt-get install -y -qq \
    opensips opensips-auth-modules opensips-http-modules \
    opensips-restclient-module opensips-json-module \
    rtpengine-daemon openjdk-21-jdk-headless nftables >/dev/null
echo "installed $(opensips -V 2>/dev/null | head -1 | sed 's/^version: //')"

step "3/9  users and directories"

id -u megatron >/dev/null 2>&1 || useradd --system --home "$VAR" --shell /usr/sbin/nologin megatron
install -d -m 0750 -o megatron -g megatron "$VAR"
install -d -m 0750 -o root -g megatron "$ETC"
# OpenSIPS reads this directory; provisioning writes into it. Both need it, so
# it is group-owned by the group they share.
install -d -m 0750 -o megatron -g megatron "$DBTEXT"

step "4/9  secrets"

if [ -f "$SECRETS" ]; then
    echo "keeping the existing $SECRETS"
else
    # GENERATED, NEVER DEFAULTED, NEVER PROMPTED. A default credential is the
    # defect this project exists to make impossible; a prompt is a credential
    # in somebody's shell history.
    umask 077
    {
        echo "# MEGATRON secrets — generated $(date -Is). Do not commit."
        echo "MEGATRON_OPERATOR_TOKEN=$(head -c 32 /dev/urandom | base64 | tr -d '=+/' | head -c 43)"
    } > "$SECRETS"
    chmod 0600 "$SECRETS"
    chown root:megatron "$SECRETS"
    chmod 0640 "$SECRETS"
    echo "generated $SECRETS (mode 0640, root:megatron)"
fi

step "5/9  build"

if [ "$SKIP_BUILD" -eq 0 ]; then
    ( cd "$REPO" && ./gradlew --no-daemon -q \
        :provisioning:installDist :switch-api:installDist :bot:installDist ) \
        || fatal "the build failed"
fi
for service in provisioning switch-api bot; do
    [ -x "$REPO/$service/build/install/$service/bin/$service" ] \
        || fatal "$service was not built; run without --skip-build"
done
echo "built provisioning, switch-api, bot"

step "6/9  configuration"

# deploy/opensips.cfg.template, NOT lab/opensips-lab-auth.cfg. The lab config
# says at the top that it is not a production config and it means it: it
# relays every call to a SIPp listener on 127.0.0.1:5070. The deploy template
# is derived from it -- same hard-won details -- with the fake carrier replaced
# by the route the authorizer returns per call.
sed -e "s|@DOMAIN@|$DOMAIN|g" \
    "$REPO/deploy/opensips.cfg.template" > /etc/opensips/megatron.cfg
chmod 0644 /etc/opensips/megatron.cfg
grep -q '@DOMAIN@' /etc/opensips/megatron.cfg \
    && fatal "the config template still has unsubstituted placeholders"

# db_text needs a table version file, and the number is not guessable: the
# module refuses to start against a mismatch, at FIXUP -- so `opensips -C`
# reports the config as fine and the service then fails to start.
cat > "$DBTEXT/version" <<'EOF'
table_name(str) table_version(int)
subscriber:8
EOF

# An empty subscriber table so OpenSIPS can start before the first customer
# exists. Header only -- three columns, no ha1b: db_text validates every
# declared column and rejects a null field, so one empty value stops the WHOLE
# table loading and every REGISTER gets a 500.
[ -f "$DBTEXT/subscriber" ] || cat > "$DBTEXT/subscriber" <<'EOF'
username(str) domain(str) ha1(str)
EOF
chown -R megatron:megatron "$DBTEXT"
chmod 0640 "$DBTEXT/subscriber"

sed -e "s|@DOMAIN@|$DOMAIN|g" -e "s|@REPO@|$REPO|g" \
    "$REPO/deploy/megatron.env.template" > "$ETC/megatron.env"
chmod 0644 "$ETC/megatron.env"

step "7/9  services"

for unit in megatron-provisioning megatron-switch-api megatron-bot megatron-rtpengine megatron-opensips; do
    sed -e "s|@REPO@|$REPO|g" "$REPO/deploy/$unit.service" > "/etc/systemd/system/$unit.service"
done
systemctl daemon-reload

systemctl enable --now megatron-rtpengine megatron-provisioning megatron-switch-api >/dev/null
systemctl restart megatron-rtpengine megatron-provisioning megatron-switch-api
sleep 3
systemctl enable --now megatron-opensips >/dev/null
systemctl restart megatron-opensips
sleep 2

# The bot only starts once there is a token to start it with. Refusing is
# right: a bot with no operators cannot run the business, and one with an
# empty allowlist that defaulted to "everyone" would hand it to strangers.
if grep -q '^MEGATRON_TELEGRAM_TOKEN=.' "$SECRETS" 2>/dev/null; then
    systemctl enable --now megatron-bot >/dev/null
    systemctl restart megatron-bot
    echo "started the Telegram bot"
else
    echo "NOT starting the Telegram bot: no MEGATRON_TELEGRAM_TOKEN in $SECRETS."
    echo "  Add it and MEGATRON_OPERATOR_TELEGRAM_IDS, then:"
    echo "    sudo systemctl enable --now megatron-bot"
fi

step "8/9  firewall"

# Copied rather than templated: the ruleset deliberately binds to no address.
# Pinning it to one detected IP breaks the box the day it gains a second
# interface, and the properties that matter here are about PORTS.
cp "$REPO/deploy/nftables.conf.template" /etc/nftables.conf
nft -c -f /etc/nftables.conf || fatal "the firewall ruleset is invalid"
systemctl enable --now nftables >/dev/null
nft -f /etc/nftables.conf
echo "firewall loaded"

step "9/9  verify"

fail=0
check() {
    if eval "$2" >/dev/null 2>&1; then
        echo "  ok    $1"
    else
        echo "  FAIL  $1"
        fail=1
    fi
}

check "provisioning answers"  "curl -sf -m 5 -H 'Authorization: Bearer $(grep MEGATRON_OPERATOR_TOKEN "$SECRETS" | cut -d= -f2)' http://127.0.0.1:8081/v1/customers"
check "switch-api answers"    "curl -sf -m 5 http://127.0.0.1:8082/v1/health"
check "rtpengine is up"       "pgrep -x rtpengine"
check "the switch owns 5060"  "ss -lunp | grep -q ':5060.*opensips'"
check "the switch reloads"    "curl -sf -m 5 http://127.0.0.1:8888/mi -H 'Content-Type: application/json' -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"dbt_reload\"}'"

# Loopback-only, checked rather than assumed: these two move money and issue
# credentials, and on a public interface either one is the whole business.
check "provisioning is not public" "! ss -lntp | grep -E ':8081' | grep -qv '127.0.0.1'"
check "switch-api is not public"   "! ss -lntp | grep -E ':8082' | grep -qv '127.0.0.1'"

echo
if [ "$fail" -ne 0 ]; then
    echo "Something is not right. Start with:  journalctl -u megatron-provisioning -u megatron-opensips -n 50"
    exit 1
fi

cat <<EOF

MEGATRON is running on $DOMAIN.

  operator token   $SECRETS  (mode 0640 — it is not printed here on purpose)
  database         $VAR/megatron.db
  switch config    /etc/opensips/megatron.cfg
  credentials      $DBTEXT/subscriber  (written by provisioning, reloaded automatically)

Next:
  1. Point $DOMAIN at $PUBLIC_IP.
  2. Create a plan and a rate, then a customer — see deploy/README.md.
  3. For the Telegram bot, add MEGATRON_TELEGRAM_TOKEN and
     MEGATRON_OPERATOR_TELEGRAM_IDS to $SECRETS and start megatron-bot.

EOF
