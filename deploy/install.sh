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

# TWO ADDRESSES, NOT ONE, AND CONFLATING THEM COSTS YOU AUDIO.
#
# BIND_IP is the address on this machine. ADVERTISE_IP is what we put in SDP
# so the far end knows where to send RTP. On any NAT'd host -- which is every
# EC2, GCE and most VPS instances -- they are DIFFERENT, and the local one is
# a 172.16/12 or 10/8 address the internet cannot route.
#
# The first version of this script called `ip route get` "the public IP". On
# this very box that returned 172.31.6.145. Deployed as-is, every call would
# have connected and carried silence, which is the single hardest VoIP fault
# to diagnose and the one this whole project treats as a money-losing failure.
BIND_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')
[ -n "$BIND_IP" ] || fatal "could not determine this machine's IP address"

if [ -z "$PUBLIC_IP" ]; then
    # Cloud metadata, best-effort and quickly. IMDSv2 first because AWS
    # increasingly refuses v1; a short timeout because on a box that is NOT in
    # a cloud this endpoint is a black hole.
    TOKEN=$(curl -fsS -m 2 -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)
    if [ -n "$TOKEN" ]; then
        PUBLIC_IP=$(curl -fsS -m 2 -H "X-aws-ec2-metadata-token: $TOKEN" \
            "http://169.254.169.254/latest/meta-data/public-ipv4" 2>/dev/null || true)
    fi
fi

if [ -z "$PUBLIC_IP" ]; then
    PUBLIC_IP=$BIND_IP
fi

echo "domain       $DOMAIN"
echo "bind         $BIND_IP"
echo "advertise    $PUBLIC_IP"

case "$PUBLIC_IP" in
    10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*|127.*)
        # Correct on a box with a real public IP on its interface, and a
        # silent disaster on a NAT'd one, so it is said out loud rather than
        # assumed either way.
        echo
        echo "  NOTE: $PUBLIC_IP is a private address, so that is what this switch will"
        echo "  advertise in SDP. If this machine is behind NAT, audio will not reach it"
        echo "  and every call will connect with silence. Re-run with:"
        echo "      --public-ip <the address customers reach you on>"
        ;;
esac

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

# AND ANYTHING ELSE HOLDING 5060, WHICH MASKING A UNIT DOES NOT COVER.
#
# A hand-started `opensips -f something.cfg` keeps the port, our switch cannot
# bind, and systemd reports only "Job for megatron-opensips.service failed
# because a timeout was exceeded" -- because with Type=forking the parent
# exits 0 and the child dies before writing a pidfile. Nothing in that message
# mentions the port. Meanwhile `ss` still shows an opensips on 5060, so even
# a careful check afterwards says the switch is up.
SQUATTER=$(ss -lunp 2>/dev/null | awk '/:5060 /{print $NF}' \
    | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2)
if [ -n "${SQUATTER:-}" ]; then
    OWNER=$(ps -p "$SQUATTER" -o args= 2>/dev/null | head -1)
    case "$OWNER" in
        *"/etc/opensips/megatron.cfg"*)
            systemctl stop megatron-opensips 2>/dev/null || true
            ;;
        *)
            fatal "something else is already listening on UDP 5060 and it is not
  ours, so this switch cannot start:

      pid $SQUATTER  $OWNER

  Stop it and run this again. (Masking the packaged unit does not cover a
  process started by hand.)"
            ;;
    esac
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

# INSTALLED TO /opt, NOT RUN FROM THE BUILD TREE.
#
# The units set ProtectHome=yes, which makes /home invisible to the service —
# so pointing ExecStart at a checkout under /home/<someone> produced
# "status=203/EXEC", a systemd error that says only that it could not execute
# the binary and nothing about why. Hardening that makes your own program
# unreachable is worse than no hardening, because it fails in a way that reads
# like a broken build.
#
# It is also simply where a service belongs: running one out of a developer's
# home directory means a `git checkout` restarts the business.
install -d -m 0755 /opt/megatron
for service in provisioning switch-api bot; do
    rm -rf "/opt/megatron/$service"
    cp -r "$REPO/$service/build/install/$service" "/opt/megatron/$service"
done
chown -R root:megatron /opt/megatron
chmod -R a+rX /opt/megatron
echo "installed provisioning, switch-api, bot to /opt/megatron"

step "6/9  configuration"

# deploy/opensips.cfg.template, NOT lab/opensips-lab-auth.cfg. The lab config
# says at the top that it is not a production config and it means it: it
# relays every call to a SIPp listener on 127.0.0.1:5070. The deploy template
# is derived from it -- same hard-won details -- with the fake carrier replaced
# by the route the authorizer returns per call.
sed -e "s|@DOMAIN@|$DOMAIN|g" -e "s|@PUBLIC_IP@|$PUBLIC_IP|g" \
    "$REPO/deploy/opensips.cfg.template" > /etc/opensips/megatron.cfg
chmod 0644 /etc/opensips/megatron.cfg
if grep -q '@[A-Z_]*@' /etc/opensips/megatron.cfg; then
    fatal "the switch config still has unsubstituted placeholders: " \
        "$(grep -o '@[A-Z_]*@' /etc/opensips/megatron.cfg | sort -u | tr '\n' ' ')"
fi

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
    sed -e "s|@REPO@|$REPO|g" -e "s|@BIND_IP@|$BIND_IP|g" -e "s|@PUBLIC_IP@|$PUBLIC_IP|g" \
        "$REPO/deploy/$unit.service" > "/etc/systemd/system/$unit.service"
    # An unsubstituted placeholder in a unit file is a service that fails to
    # start with an error about a value nobody typed.
    if grep -q '@[A-Z_]*@' "/etc/systemd/system/$unit.service"; then
        fatal "$unit.service still has unsubstituted placeholders: " \
            "$(grep -o '@[A-Z_]*@' "/etc/systemd/system/$unit.service" | sort -u | tr '\n' ' ')"
    fi
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
  2. Prove it carries a call:  sudo bash deploy/smoke-test.sh
EOF

# Told what to do, not told to do what is already done. A closing checklist
# that lists a step you completed two minutes ago trains people to skip the
# whole thing.
if systemctl is-active --quiet megatron-bot; then
    echo "  3. The Telegram bot is running. Message it and send /help."
else
    echo "  3. For the Telegram bot, add MEGATRON_TELEGRAM_TOKEN and"
    echo "     MEGATRON_OPERATOR_TELEGRAM_IDS to $SECRETS, then:"
    echo "         sudo systemctl enable --now megatron-bot"
fi
echo
