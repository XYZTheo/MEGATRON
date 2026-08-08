# Deploying MEGATRON on one box

```sh
git clone <repo> megatron && cd megatron
sudo bash deploy/install.sh --domain sip.example.com
```

That is the whole thing. It installs OpenSIPS and rtpengine, builds the three
services, generates credentials, renders the switch config, installs systemd
units, loads a firewall, and then **checks that what it just built actually
works** — including that the two services which move money are not listening
on a public interface.

Point `sip.example.com` at the box, and it is a switch.

## What you get

| | |
|---|---|
| **provisioning** | `127.0.0.1:8081` — customers, plans, rates, balances, credentials |
| **switch-api** | `127.0.0.1:8082` — the money path: authorize a call, settle it, emit the CDR |
| **bot** | the Telegram interface the business is actually operated through |
| **OpenSIPS** | `0.0.0.0:5060` — the only public service |
| **rtpengine** | anchors media so the switch can tell a conversation from silence |

The database is `/var/lib/megatron/megatron.db`. Credentials for the switch are
rendered to `/etc/opensips/dbtext/subscriber` and the switch is told to reload
them automatically.

## There is no default password

Every credential is generated into `/etc/megatron/secrets.env` (mode 0640,
`root:megatron`) and never printed. There is no prompt for one either — a
prompt is a credential in somebody's shell history.

This is not a preference. MagnusBilling shipped `root`/`magnus`, and that one
default is responsible for a large share of the compromised installs this
product exists to replace. **The installer has no path that produces an
insecure install**, which is a stronger property than "the installer warns
you".

## First customer

```sh
TOKEN=$(sudo grep MEGATRON_OPERATOR_TOKEN /etc/megatron/secrets.env | cut -d= -f2)
API=http://127.0.0.1:8081
auth=(-H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json')

# Your carrier. Do this FIRST: calls are refused until there is somewhere to
# send them, because allowing one with nowhere to go would reserve a
# customer's balance against a call that connects to nothing and then bill it.
# remote_ips is what the carrier sends to you from, and it is required — an
# inbound trunk that accepts from anywhere is an open relay.
curl -s "${auth[@]}" -H "Idempotency-Key: trunk-1" \
  -d '{"name":"carrier-a","direction":"outbound","host":"203.0.113.10",
       "port":5060,"remote_ips":["203.0.113.10"],"transport":"udp"}' \
  $API/v1/trunks

# A plan
PLAN=$(curl -s "${auth[@]}" -H "Idempotency-Key: plan-1" \
  -d '{"name":"Retail","currency":"USD"}' $API/v1/plans | jq -r .id)

# What it costs. Money is integer micro-units: 10000 = one US cent per minute.
curl -s "${auth[@]}" -H "Idempotency-Key: rates-1" -X PUT \
  -d '{"rates":[{"prefix":"1","description":"US",
       "sell_micros_per_minute":10000,"increment_seconds":60}]}' \
  $API/v1/plans/$PLAN/rates

# A login. The password is returned ONCE and cannot be looked up again.
curl -s "${auth[@]}" -H "Idempotency-Key: cust-1" \
  -d "{\"handle\":\"acme\",\"plan_id\":\"$PLAN\",\"opening_balance_micros\":25000000}" \
  $API/v1/customers | jq
```

Within `MEGATRON_SUBSCRIBER_INTERVAL_SECONDS` (15 by default) that customer can
register a softphone and dial.

**`Idempotency-Key` is required on every mutation.** A bot on a phone network
times out after the server has committed and then retries; without the key
that is a double credit, every time.

## The Telegram bot

It is how the business is operated — there is no web panel in the workflow.
It does not start until you give it a token, and it refuses to start with an
empty operator list rather than defaulting to "everyone".

1. `/newbot` to [@BotFather](https://t.me/BotFather) for a token.
2. [@userinfobot](https://t.me/userinfobot) for your numeric Telegram user id.
3. Append both to `/etc/megatron/secrets.env`:

   ```
   MEGATRON_TELEGRAM_TOKEN=123456:AA...
   MEGATRON_OPERATOR_TELEGRAM_IDS=11111111,22222222
   ```

4. `sudo systemctl enable --now megatron-bot`

Operators get `/newuser /rotate /credit /suspend /enable /who /users`;
customers get `/balance` and `/cli`. A reply carrying a SIP password is never
posted into a group chat — it goes to your private chat, and if the bot cannot
message you privately the group is told to fix that rather than shown the
password.

## Upgrading

```sh
git pull
sudo bash deploy/install.sh --domain sip.example.com
```

Idempotent: it rebuilds, re-renders the config, and restarts. Secrets and the
database are left alone. Schema changes are applied additively at startup — an
upgrade that can destroy data will eventually meet a database somebody cared
about, so nothing here drops or rewrites a column.

## Checking on it

```sh
systemctl status megatron-\*
journalctl -u megatron-opensips -f | grep MEGATRON   # decisions, per call
journalctl -u megatron-provisioning -f               # credential exports
```

The switch logs one line per decision: `allow <account> -> <number> for <n>s`,
and on hangup a settlement with the amount charged. A `NO-MEDIA` flag on a CDR
means the call connected and carried no audio — billed, because it happened,
but marked, because that is what a dispute will be about.

## What this deployment is not

- **Not multi-node.** One box, one realm. The edge/core split in `edge/` and
  `core/` is the design for scaling out; it has never carried a call and is
  not what this installs.
- **Not PostgreSQL.** SQLite, which is genuinely adequate for the provisioning
  data of a v1 deployment — hundreds of customers and a few thousand
  transactions is not a scale problem. CDR volume is, which is why CDRs are
  not in that database.
- **Not load-tested.** rtpengine runs in userspace here; the kernel forwarding
  module is a separate build that fails on some cloud kernels. That is a
  throughput ceiling, not a correctness problem.
- **Not a substitute for provider DDoS scrubbing.** A flood that fills the
  pipe is not solvable on the box. What is solvable, decisively, is the
  application-layer flood that kills a MagnusBilling install on the same
  hardware.
