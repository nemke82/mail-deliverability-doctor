---
name: mail-deliverability-doctor
description: Diagnose why email bounces, is rejected, or lands in spam, and produce the exact fix. Use when mail to Gmail, Outlook/Hotmail, iCloud or Yahoo bounces or goes to junk, for bounce codes such as S3140, 5.7.26, 5.7.515, HM08 or TSS04, for blocklist (Spamhaus, Barracuda) listings, or to audit or set up SPF, DKIM, DMARC, reverse DNS (PTR), HELO, MTA-STS and TLS. Works for any domain from any machine with dig, and on Postfix or Exim servers (cPanel, Plesk, DirectAdmin or none). Read-only; it prints corrected DNS records and config changes for the user to apply.
---

# Mail deliverability doctor

Find out why mail is not delivered or lands in spam, fix the cause, and only then
ask for delisting.

## Ground rules

- **Read-only.** The scripts query DNS, open an SMTP connection without sending
  mail, and read logs. They never change DNS, configuration or the mail queue.
- **Stop the source before delisting.** If a mailbox, script or relay is sending
  spam, deal with that first; delisting while spam flows gets the IP relisted.
- **Ask before changing anything.** Show proposed DNS records and config edits,
  explain each in one sentence, and wait for approval. Back up config files first.
- **Privacy.** Recipient addresses are masked in the reports. Do not paste message
  bodies or full recipient lists back to the user unless they ask.
- **DNS changes are slow.** Old values stay cached for the TTL. Re-check after the
  TTL, not straight away.

## Scripts

All in `scripts/`, bash plus `dig` (bind-utils / dnsutils), `openssl`, `curl`, `timeout`.

| Script | Run where | Purpose |
|---|---|---|
| `check-domain.sh [-i IP] [-s SEL] [-t] DOMAIN` | anywhere | MX, SPF (tree, lookup count, result for a sending IP), DKIM keys, DMARC (incl. external report authorization), MTA-STS, TLS-RPT, BIMI |
| `check-ip.sh [-H HELO] IP...` | mail server preferred | PTR + forward confirmation, generic-name check, HELO, 8 public blocklists with delisting links |
| `check-smtp.sh [-p PORT] HOST` | host with outbound port 25 | banner, EHLO, STARTTLS, certificate validity and expiry; sends no mail |
| `check-server.sh [-n LINES] [-L LOG] [-o]` | the mail server, as root | MTA, HELO, outbound IPs, DKIM signing, queue, bounces/deferrals grouped by cause and recipient domain, top senders |
| `parse-headers.sh FILE` | anywhere | SPF/DKIM/DMARC as the receiver saw them, alignment, one-click unsubscribe, spam scores, Received path |
| `gen-records.sh -d DOMAIN [...]` | anywhere | Prints merged SPF, staged DMARC, DKIM key steps, MTA-STS/TLS-RPT records; publishes nothing |

`MDD_RESOLVER=IP` sends DNS queries to a chosen resolver. Spamhaus refuses queries
from large public resolvers; `check-ip.sh` reports those answers as "query refused",
never as listings.

## Workflow

### 1. Get the symptom precisely

Ask for (or find in the logs) the **exact bounce text**, the sender domain, the
recipient provider, and whether it is a bounce, a delay, or delivered-to-spam. A
bounce code usually names the cause directly: look it up in
`references/provider-codes.md`.

### 2. Audit the domain

`bash scripts/check-domain.sh -i SENDING_IP DOMAIN`

Add `-s SELECTOR` when you know the DKIM selector (from the `s=` tag of a
`DKIM-Signature` header); without it common selectors are probed. Fix FAIL findings
first. If the domain sends through several systems (own server, Microsoft 365,
an ESP, a CRM), each one must pass SPF or DKIM aligned with the From domain.

### 3. Check the sending IP

`bash scripts/check-ip.sh -H HELO_NAME IP`

Missing or mismatched PTR and blocklist listings show up here. Microsoft, Apple,
Gmail and Yahoo use private reputation, so a clean result here does not rule out
an S3140 or HM08 block.

### 4. On the mail server, read the logs

`sudo bash scripts/check-server.sh`

The "By cause" table shows which problem actually costs deliveries and at which
providers. The "Top senders" table shows whether one mailbox or script is
responsible for the volume; a sudden outlier usually means stolen credentials or
an exploited web form. Handle that first (`references/mta-config.md`, "Stopping a
spam source").

### 5. Look at a real message

When mail is delivered but lands in spam, or DMARC fails, get the raw headers of a
received copy (Gmail "Show original", Outlook "View message source") and run
`bash scripts/parse-headers.sh message.eml`. It shows which check failed and
whether SPF/DKIM are aligned with the From domain, which is the usual hidden
problem with ESPs and CRMs.

### 6. Propose the fix

- DNS: `bash scripts/gen-records.sh -d DOMAIN -i IP -I ESP_INCLUDE -r DMARC_MAILBOX [-k SELECTOR] [-s]`.
  It merges with the published SPF instead of replacing it. Rules and pitfalls:
  `references/records.md`.
- Server: HELO, IPv6, DKIM signing per stack in `references/mta-config.md`.
- PTR: only the owner of the IP (hosting provider) can set it; give the user the
  exact name to request.
- Delisting: after the cause is fixed, use the portal for each provider or list
  (`references/provider-codes.md`).

### 7. Verify

Re-run `check-domain.sh` after the TTL has passed, send a test message to a Gmail
and an Outlook.com mailbox, and run `parse-headers.sh` on the received copies.
Expect SPF pass, DKIM pass with d= the From domain, and DMARC pass.

### 8. Report

Summarise for the user: the cause, what was changed where (DNS, server, provider
portals), what is still pending (PTR ticket, delisting review, DMARC stage), and
what to watch: DMARC aggregate reports, Google Postmaster Tools, Microsoft SNDS,
and the bounce summary from `check-server.sh` in a few days.
