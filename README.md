<p align="center"><img src="assets/logo.svg" width="128" alt="mail-deliverability-doctor logo"></p>

# mail-deliverability-doctor

An agent skill that finds out why email bounces or lands in spam, and gives you
the exact fix: DNS records, server settings and the right delisting portal.

Get it on [Agensi](https://www.agensi.io/skills/mail-deliverability-doctor) or
clone this repo (see [Install](#install)).

Ask your coding agent something like *"mail to Hotmail bounces with S3140"*,
*"our invoices go to Gmail spam"* or *"set up DMARC for example.com"* and it will:

1. read the exact bounce codes and map them to a cause,
2. audit the domain: MX, SPF (with the 10-lookup limit and a pass/fail for your
   sending IP), DKIM keys, DMARC, MTA-STS, TLS-RPT, BIMI,
3. check the sending IP: reverse DNS, HELO, and 8 public blocklists,
4. on the mail server, group recent bounces and deferrals by cause and provider,
   and spot a compromised mailbox or script sending spam,
5. explain a received message's SPF/DKIM/DMARC result and alignment,
6. print corrected records (SPF merged with what you already have, a staged
   DMARC rollout, DKIM key steps), and change nothing until you approve.

Works for any domain from any machine with `dig`, and on Postfix or Exim servers
with cPanel, Plesk, DirectAdmin or no panel. Knows Gmail, Outlook.com/Microsoft 365,
iCloud and Yahoo bounce codes and their sender requirements.

## What is inside

```
SKILL.md                    instructions the agent follows
scripts/check-domain.sh     DNS audit: MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI
scripts/check-ip.sh         PTR, forward confirmation, HELO, blocklists
scripts/check-smtp.sh       banner, EHLO, STARTTLS and certificate (sends no mail)
scripts/check-server.sh     MTA, queue, DKIM signing, bounces grouped by cause, top senders
scripts/parse-headers.sh    SPF/DKIM/DMARC and alignment from a received message
scripts/gen-records.sh      prints corrected DNS records (never publishes)
references/                 provider codes, record rules, per-MTA configuration
tests/run.sh                offline tests on DNS fixtures and synthetic logs
```

Needs bash, `dig` (bind-utils or dnsutils), `openssl`, `curl` and `timeout`. Everything is
read-only: no DNS, configuration or queue changes.

## Install

### From Agensi

1. Download the skill zip from <https://www.agensi.io/skills/mail-deliverability-doctor>.
2. Unzip it into your agent's skills directory. For Claude Code:

   ```sh
   mkdir -p ~/.claude/skills/mail-deliverability-doctor
   unzip mail-deliverability-doctor.zip -d ~/.claude/skills/mail-deliverability-doctor
   ```

   For a single project only, use `.claude/skills/mail-deliverability-doctor` inside it.
3. Start a new session. The skill loads when you describe a mail delivery problem,
   or ask for it by name.

### From GitHub

```sh
git clone https://github.com/nemke82/mail-deliverability-doctor ~/.claude/skills/mail-deliverability-doctor
```

Update later with `git -C ~/.claude/skills/mail-deliverability-doctor pull`.

### Other agents

Any agent that supports `SKILL.md` skills: copy the folder (or unzip the Agensi
download) into that agent's skills directory.

### Without an agent

```sh
bash scripts/check-domain.sh -i 203.0.113.7 example.com
bash scripts/check-ip.sh -H mail.example.com 203.0.113.7
sudo bash scripts/check-server.sh
bash scripts/parse-headers.sh message.eml
bash scripts/gen-records.sh -d example.com -i 203.0.113.7 -r dmarc@example.com -k s2026
```

## Examples

```sh
# check a specific DKIM selector and test STARTTLS on every MX
bash scripts/check-domain.sh -s selector1 -t example.com

# use a specific resolver (Spamhaus refuses large public resolvers)
MDD_RESOLVER=127.0.0.1 bash scripts/check-ip.sh 203.0.113.7

# journald-only Postfix
journalctl -u postfix --since -1d | sudo bash scripts/check-server.sh -o -L -

# test submission port TLS
bash scripts/check-smtp.sh -p 587 smtp.example.com
```

## Tests

```sh
bash tests/run.sh          # KEEP=1 keeps the generated reports
```

The tests run offline from a DNS fixture file and use documentation IP ranges
(RFC 5737) and example domains only.

## License

MIT, see [LICENSE](LICENSE).
