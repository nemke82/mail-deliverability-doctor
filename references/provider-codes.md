# Bounce causes and provider codes

`check-server.sh` groups failed deliveries into the causes below. Provider codes
and wording change over time: always quote the exact bounce text to the user and
follow any URL the bounce itself contains, since it is the most current source.

| Cause | Typical text | What it means | Fix, in order |
|---|---|---|---|
| `microsoft-blocklist` | `550 5.7.1 ... part of their network is on our block list (S3140)` / `(S3150)` | Outlook.com / Hotmail / Live block the sending IP on reputation. Not a public DNSBL. | 1. Make sure nothing is spamming (top senders table). 2. Fix PTR, SPF, DKIM, DMARC. 3. Request mitigation at https://sender.office.com. 4. Sign up for SNDS and JMRP to watch the IP. |
| `microsoft-banned` | `5.7.606`–`5.7.649 Access denied, banned sending IP`, `5.7.511 banned sender` | Microsoft 365 (business tenants) blocks the IP; 5.7.511 needs a support case. | Delist via https://sender.office.com; for 5.7.511 open a case with the address the bounce gives. |
| `microsoft-auth` | `550 5.7.515 Access denied, sending domain ... does not meet the required authentication level` | High-volume sender (over about 5,000 messages a day to Outlook.com) without SPF + DKIM + DMARC passing and aligned. | Publish all three, aligned with the From domain (DMARC p=none is the minimum). |
| `apple-policy` | `554 5.7.1 [HM08] Message rejected due to local policy`, other `HMxx`/`CSxx` codes | iCloud (icloud.com, me.com, mac.com) rejects on reputation or authentication. | Fix authentication and PTR first, then follow the postmaster instructions linked from Apple's "iCloud Mail postmaster" support page. Recovery often takes days. |
| `auth-dmarc` | Gmail `550-5.7.26 ... unauthenticated`, `DMARC policy`, Yahoo `554 5.7.9` | The message failed DMARC, or had neither SPF nor DKIM. | Check a received copy with `parse-headers.sh`; align DKIM (d=From domain) or SPF. |
| `auth-spf` | Gmail `5.7.27`, `SPF check failed` | Sending IP not authorized by the envelope domain's SPF. | `check-domain.sh -i IP domain`, then `gen-records.sh -i IP`. |
| `auth-dkim` | `DKIM signature invalid`, `body hash did not verify` | Signature missing or broken (key mismatch, message modified after signing). | Verify the selector key (`check-domain.sh -s`), stop footer/disclaimer tools that modify signed mail. |
| `ptr` | Gmail `550-5.7.25 ... PTR record`, `reverse DNS`, `does not have a PTR` | The IP has no reverse DNS or it does not match. Over IPv6 Gmail is strict about this. | Ask the IP owner (hosting provider) for a PTR to the HELO name, with a matching A/AAAA. Or disable outbound IPv6. |
| `gmail-rate` | `421-4.7.28` / `550-5.7.28 ... unusual rate of unsolicited mail` | Gmail throttles the IP or domain for volume or complaints. | Slow down, remove unengaged recipients, check Google Postmaster Tools spam rate (keep it under 0.3%, ideally under 0.1%). |
| `reputation` | `550-5.7.1 ... likely unsolicited mail`, `very low reputation` | Content plus domain/IP reputation judged as spam. | Postmaster Tools reputation; fix list hygiene and complaints; authentication alone will not fix it. |
| `yahoo-deferral` | `421 4.7.0 [TSS04] Messages ... temporarily deferred due to unexpected volume or user complaints` | Yahoo/AOL defer on reputation. Messages retry. | Lower volume, check complaints, register at the Yahoo Sender Hub (senders.yahooinc.com). |
| `yahoo-block` | `[TSS09]`, `[TSS05]` | Yahoo/AOL refuse the IP for longer. | Fix the cause, then use the Yahoo Sender Hub support form. |
| `dnsbl` | `blocked using zen.spamhaus.org`, `listed at`, `RBL` | A public blocklist lists the IP (or a URL/domain in the message). | `check-ip.sh IP`; stop the spam source, then delist on the list's own page. |
| `content-spam` | `5.7.1 ... spam`, `message content rejected` | Content filter. | Check links (shorteners, listed domains), attachments, and the HTML. |
| `tls` | `STARTTLS required`, `certificate` | TLS failed between the servers. | `check-smtp.sh MX` from the sending server; update OpenSSL/CA bundle; check MTA-STS policies. |
| `connection` | `Connection timed out`, `retry timeout exceeded` | No SMTP connection. | Outbound port 25 blocked by the provider/firewall, or the remote MX is down. Test with `check-smtp.sh`. |
| `throttled` | `421`, `4.7.0`, `try again later`, `too many` | Generic rate limit or greylisting. | Usually transient; act only if it persists for hours. |
| `bad-recipient` | `5.1.1 user unknown`, `Unrouteable address` | Address does not exist. | Remove it from lists. Many hard bounces hurt reputation. |
| `mailbox-full` | `5.2.2`, `over quota` | Recipient side. | Nothing to fix on the sender. |

## Requirements the large mailbox providers enforce

Gmail and Yahoo (from February 2024) and Microsoft Outlook.com (from May 2025)
require, broadly:

- **Everyone:** SPF or DKIM, valid forward-confirmed reverse DNS for the sending
  IP, TLS, low spam-complaint rate, RFC 5322 compliant messages.
- **Bulk senders** (roughly 5,000+ messages a day to that provider): SPF **and**
  DKIM, a DMARC record (p=none is enough), the From domain aligned with SPF or
  DKIM, and for marketing mail one-click unsubscribe (RFC 8058:
  `List-Unsubscribe` + `List-Unsubscribe-Post: List-Unsubscribe=One-Click`),
  honored within two days.

Check the providers' current sender guidelines for exact numbers.

## Monitoring portals

- Google Postmaster Tools: https://postmaster.google.com (domain reputation, spam rate, auth)
- Microsoft SNDS: https://sendersupport.olc.protection.outlook.com/snds/ (IP data and traps)
- Microsoft delisting: https://sender.office.com
- Yahoo Sender Hub: https://senders.yahooinc.com (complaint feedback loop, support)
- Spamhaus lookup and removal: https://check.spamhaus.org
- DMARC aggregate reports: any DMARC report parser; the `rua` mailbox receives XML.
