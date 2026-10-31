#!/usr/bin/env bash
# Offline tests: DNS answers come from a fixture file, logs and headers are
# synthetic. Only documentation IPs (RFC 5737) and example domains are used.
# KEEP=1 keeps the work directory.
# shellcheck disable=SC2015  # 'cond && ok || bad' is intended: ok/bad never fail
set -uo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$root/scripts
work=$(mktemp -d)
[ -n "${KEEP:-}" ] || trap 'rm -rf "$work"' EXIT
pass=0; fail=0

ok()   { pass=$((pass + 1)); }
bad()  { fail=$((fail + 1)); printf 'FAIL: %s\n' "$*"; }
has()  { grep -qF -- "$2" "$1" && ok || bad "$3 (missing: $2)"; }
hasnt(){ grep -qF -- "$2" "$1" && bad "$3 (unexpected: $2)" || ok; }
eq()   { [ "$1" = "$2" ] && ok || bad "$3 (got '$1', want '$2')"; }

# ------------------------------------------------ DKIM test keys
key() { openssl genrsa "$1" 2>/dev/null | openssl rsa -pubout -outform DER 2>/dev/null | openssl base64 -A; }
k2048=$(key 2048); k1024=$(key 1024)

# ------------------------------------------------ DNS fixture
F=$work/dns.tsv
T=$'\t'
cat > "$F" <<EOF
good.example${T}MX${T}10 mail.good.example.
mail.good.example${T}A${T}192.0.2.10
good.example${T}TXT${T}v=spf1 mx ip4:192.0.2.0/28 include:_spf.esp.example ~all
good.example${T}TXT${T}google-site-verification=abc
_spf.esp.example${T}TXT${T}v=spf1 ip4:203.0.113.0/24 -all
default._domainkey.good.example${T}TXT${T}v=DKIM1; k=rsa; p=$k2048
_dmarc.good.example${T}TXT${T}v=DMARC1; p=reject; rua=mailto:dmarc@good.example
10.2.0.192.in-addr.arpa${T}PTR${T}mail.good.example.
_mta-sts.good.example${T}TXT${T}v=STSv1; id=2026010101
_smtp._tls.good.example${T}TXT${T}v=TLSRPTv1; rua=mailto:tls@good.example
bad.example${T}TXT${T}v=spf1 +all
bad.example${T}TXT${T}v=spf1 ip4:192.0.2.1 -all
bad.example${T}MX${T}10 192.0.2.99
s1._domainkey.bad.example${T}TXT${T}v=DKIM1; k=rsa; p=$k1024
heavy.example${T}TXT${T}v=spf1 include:i1.example include:i2.example include:i3.example include:i4.example include:i5.example include:i6.example ~all
_dmarc.heavy.example${T}TXT${T}v=DMARC1; p=none; rua=mailto:reports@dmarc-vendor.example
EOF
for i in 1 2 3 4 5 6; do
  printf 'i%s.example\tTXT\tv=spf1 a mx ip4:198.51.100.%s ?all\n' "$i" "$i" >> "$F"
  printf 'i%s.example\tA\t198.51.100.%s\n' "$i" "$((i + 100))" >> "$F"
done
cat >> "$F" <<EOF
loop.example${T}TXT${T}v=spf1 include:loop.example -all
redir.example${T}TXT${T}v=spf1 redirect=good.example
sub.good.example${T}TXT${T}v=spf1 a:mail.good.example -all
7.100.51.198.in-addr.arpa${T}PTR${T}198-51-100-7.dynamic.isp.example.
198-51-100-7.dynamic.isp.example${T}A${T}198.51.100.7
5.113.0.203.in-addr.arpa${T}PTR${T}mail.other.example.
10.2.0.192.zen.spamhaus.org${T}A${T}127.0.0.2
10.2.0.192.zen.spamhaus.org${T}TXT${T}https://check.spamhaus.org/sbl/query/SBL0000
7.100.51.198.zen.spamhaus.org${T}A${T}127.255.255.254
7.100.51.198.dnsbl-1.uceprotect.net${T}A${T}127.0.0.2
EOF
cat >> "$F" <<'EOF2'
two.example	TXT	v=spf1 include:$(touch${IFS}PWNED).example a:`touch${IFS}PWNED` -all
_dmarc.two.example	TXT	v=DMARC1; p=none
_dmarc.two.example	TXT	v=DMARC1; p=$(touch PWNED)
EOF2
export MDD_DNS_FIXTURE=$F

# ------------------------------------------------ lib
# shellcheck source=../scripts/lib.sh
. "$S/lib.sh"
eq "$(mdd_rev 192.0.2.10)" "10.2.0.192" "rev4"
eq "$(mdd_expand6 2001:db8::1)" "20010db8000000000000000000000001" "expand6"
eq "$(mdd_rev 2001:db8::1 | cut -c1-9)" "1.0.0.0.0" "rev6 start"
eq "$(mdd_org_domain mail.shop.example.co.uk)" "example.co.uk" "org co.uk"
eq "$(mdd_org_domain a.b.good.example)" "good.example" "org plain"
mdd_in_cidr 192.0.2.10 192.0.2.0/28 && ok || bad "cidr in"
mdd_in_cidr 192.0.2.17 192.0.2.0/28 && bad "cidr out" || ok
mdd_in_cidr 10.0.0.1 0.0.0.0/0 && ok || bad "cidr /0"
mdd_is_ipv4 256.1.1.1 && bad "ipv4 range" || ok
mdd_is_domain 'evil;rm.example' && bad "domain validation" || ok

# ------------------------------------------------ check-domain
o=$work/good.md
bash "$S/check-domain.sh" -i 192.0.2.10 -i 203.0.113.5 -i 198.51.100.7 good.example > "$o"
has "$o" "| 192.0.2.10 | pass |" "spf pass via ip4/mx"
has "$o" "| 203.0.113.5 | pass |" "spf pass via include"
has "$o" "| 198.51.100.7 | softfail |" "spf softfail"
has "$o" "\`default\`: rsa 2048-bit" "dkim 2048 found by probe"
has "$o" "| policy (p / sp) | reject / same |" "dmarc reject"
has "$o" "DNS-querying terms: **2** of 10" "lookup count good"
hasnt "$o" "**FAIL** No SPF" "good has spf"
has "$o" "Sending IP 198.51.100.7 gets SPF 'softfail'" "softfail finding"

o=$work/bad.md
bash "$S/check-domain.sh" -s s1 -s missing bad.example > "$o"
has "$o" "has 2 SPF records" "two spf records"
has "$o" "MX 192.0.2.99 is an IP address" "mx ip"
has "$o" "1024-bit key" "dkim 1024 warn"
has "$o" "no DKIM key at missing._domainkey.bad.example" "missing selector"
has "$o" "**FAIL** No DMARC record" "no dmarc"

o=$work/heavy.md
bash "$S/check-domain.sh" -i 198.51.100.104 heavy.example > "$o"
has "$o" "SPF needs 18 DNS lookups" "too many lookups"
has "$o" "| 198.51.100.104 | pass |" "spf pass via a in include"
has "$o" "has not published heavy.example._report._dmarc.dmarc-vendor.example" "external rua auth"
has "$o" "DMARC p=none" "p=none info"

bash "$S/check-domain.sh" loop.example > "$work/loop.md"
has "$work/loop.md" "loop" "spf loop detected"
bash "$S/check-domain.sh" -i 192.0.2.10 redir.example > "$work/redir.md"
has "$work/redir.md" "| 192.0.2.10 | pass |" "redirect eval"
bash "$S/check-domain.sh" -i 192.0.2.10 sub.good.example > "$work/sub.md"
has "$work/sub.md" "(inherited from the organizational domain good.example)" "dmarc org fallback"
has "$work/sub.md" "| 192.0.2.10 | pass |" "a:host eval"
bash "$S/check-domain.sh" 'bad domain' > /dev/null 2>&1 && bad "rejects bad domain" || ok

(cd "$work" && bash "$S/check-domain.sh" -i 192.0.2.10 two.example > "$work/two.md")
[ -e "$work/PWNED" ] && bad "DNS text was executed" || ok
has "$work/two.md" "more than one DMARC record" "duplicate dmarc"
# shellcheck disable=SC2016  # literal on purpose
has "$work/two.md" 'p=$(touch PWNED)' "hostile text printed literally"

# ------------------------------------------------ check-ip
o=$work/ip.md
bash "$S/check-ip.sh" -H mail.good.example 192.0.2.10 198.51.100.7 203.0.113.5 > "$o"
has "$o" "PTR: mail.good.example (forward-confirmed)" "fcrdns ok"
has "$o" "**listed**: SBL (spam source)" "spamhaus listed"
has "$o" "SBL0000" "spamhaus txt reason"
has "$o" "query refused" "spamhaus refused not counted"
has "$o" "looks generic" "generic ptr"
has "$o" "does not resolve back to 203.0.113.5" "fcrdns fail"
has "$o" "is listed on dnsbl-1.uceprotect.net (few large" "low weight info"
bash "$S/check-ip.sh" 'x;id' > /dev/null 2>&1 && bad "rejects bad ip" || ok

# ------------------------------------------------ check-server (logs only)
cat > "$work/exim.log" <<'EOF'
2026-01-31 10:00:01 1aaaaa-000001-AA <= shop@good.example H=localhost A=dovecot_login:shop@good.example S=1200
2026-01-31 10:00:02 1aaaaa-000001-AA ** someone@hotmail.example R=dkim_lookuphost T=dkim_remote_smtp H=mx1.hotmail.example [198.51.100.20]: SMTP error from remote mail server after RCPT TO:<someone@hotmail.example>: 550 5.7.1 Unfortunately, messages from [192.0.2.10] weren't sent. Please contact your Internet service provider since part of their network is on our block list (S3140).
2026-01-31 10:00:03 1aaaaa-000002-AA ** other@hotmail.example R=dkim_lookuphost T=dkim_remote_smtp H=mx1.hotmail.example [198.51.100.20]: SMTP error from remote mail server after RCPT TO:<other@hotmail.example>: 550 5.7.1 Unfortunately, messages from [192.0.2.10] weren't sent (S3140).
2026-01-31 10:00:04 1aaaaa-000003-AA == a@gmail.example R=dkim_lookuphost T=dkim_remote_smtp defer (-44) H=mx.gmail.example [198.51.100.30]: SMTP error from remote mail server after pipelined end of data: 421-4.7.28 Our system has detected an unusual rate of unsolicited mail
2026-01-31 10:00:05 1aaaaa-000004-AA ** b@gmail.example R=dkim_lookuphost T=dkim_remote_smtp H=mx.gmail.example [198.51.100.30]: SMTP error from remote mail server after end of data: 550-5.7.26 This mail has been blocked because the sender is unauthenticated.
2026-01-31 10:00:06 1aaaaa-000005-AA == c@slow.example R=dkim_lookuphost T=dkim_remote_smtp defer (110): Connection timed out
2026-01-31 10:00:07 1aaaaa-000006-AA ** nobody@good.example: Unrouteable address
2026-01-31 10:00:08 1aaaaa-000007-AA <= info@good.example U=shopuser P=local S=900 id=x T="Order" from <info@good.example> for x@y.example
EOF
cat > "$work/postfix.log" <<'EOF'
Jan 31 10:01:00 mx postfix/smtpd[11]: 1A2B3C: client=unknown[192.0.2.50], sasl_method=LOGIN, sasl_username=sales@good.example
Jan 31 10:01:01 mx postfix/smtp[12]: 1A2B3C: to=<d@yahoo.example>, relay=mta.yahoo.example[198.51.100.40]:25, delay=1, delays=0/0/0/1, dsn=4.7.0, status=deferred (host mta.yahoo.example[198.51.100.40] said: 421 4.7.0 [TSS04] Messages from 192.0.2.10 temporarily deferred due to unexpected volume or user complaints (in reply to MAIL FROM command))
Jan 31 10:01:02 mx postfix/smtp[12]: 4D5E6F: to=<e@corp.example>, relay=mx.corp.example[198.51.100.50]:25, delay=1, delays=0/0/0/1, dsn=5.7.1, status=bounced (host mx.corp.example[198.51.100.50] said: 554 5.7.1 Service unavailable; Client host [192.0.2.10] blocked using zen.spamhaus.org (in reply to RCPT TO command))
EOF
o=$work/server.md
bash "$S/check-server.sh" -o -L "$work/exim.log" -L "$work/postfix.log" > "$o"
has "$o" "Found 8 failed delivery attempts: 5 bounces, 3 deferrals." "event count"
has "$o" "| microsoft-blocklist | 2 | 2 | hotmail.example (2)" "S3140 category"
has "$o" "| gmail-rate | 1 |" "gmail rate"
has "$o" "| auth-dmarc | 1 |" "gmail 5.7.26"
has "$o" "| yahoo-deferral | 1 |" "yahoo TSS04"
has "$o" "| dnsbl | 1 |" "dnsbl bounce"
has "$o" "| connection | 1 |" "connection defer"
has "$o" "| bad-recipient | 1 |" "unrouteable"
has "$o" "auth shop@good.example" "exim auth sender"
has "$o" "auth sales@good.example" "postfix sasl sender"
has "$o" "local user shopuser" "exim local sender"
hasnt "$o" "someone@hotmail.example" "recipients masked"
cat "$work/postfix.log" | bash "$S/check-server.sh" -o -L - > "$work/stdin.md"
has "$work/stdin.md" "Found 2 failed" "stdin log"

# ------------------------------------------------ parse-headers
cat > "$work/msg.eml" <<'EOF'
Return-Path: <bounce-123@esp-bounces.example>
Authentication-Results: mx.receiver.example;
       dkim=pass header.i=@esp.example header.s=s1 header.b=abc;
       spf=pass (receiver.example: domain of bounce-123@esp-bounces.example designates 203.0.113.5 as permitted sender) smtp.mailfrom=bounce-123@esp-bounces.example;
       dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=good.example
Received: from mta.esp.example (mta.esp.example [203.0.113.5])
        by mx.receiver.example with ESMTPS id x for <someone@receiver.example>;
        Sat, 31 Jan 2026 10:00:00 +0000
DKIM-Signature: v=1; a=rsa-sha256; d=esp.example; s=s1; h=from:to; bh=x; b=y
From: Shop <news@good.example>
To: someone@receiver.example
Subject: January offers
List-Unsubscribe: <https://esp.example/u/1>
X-MS-Exchange-Organization-SCL: 6
Date: Sat, 31 Jan 2026 10:00:00 +0000
Message-ID: <1@esp.example>

body
EOF
o=$work/hdr.md
bash "$S/parse-headers.sh" "$work/msg.eml" > "$o"
has "$o" "| SPF | pass | esp-bounces.example |" "spf result"
has "$o" "| DKIM | pass | esp.example |" "dkim result"
has "$o" "| DMARC | fail | good.example |" "dmarc result"
has "$o" "Neither SPF nor DKIM passes aligned with good.example" "alignment diagnosis"
has "$o" "List-Unsubscribe-Post: One-Click" "one-click warn"
has "$o" "Microsoft scored the message SCL 6" "scl"
has "$o" "mta.esp.example [203.0.113.5] → mx.receiver.example (ESMTPS)" "received path"
hasnt "$o" "someone@receiver.example" "address masked"

sed -e 's/d=esp.example/d=good.example/' -e 's/header.i=@esp.example/header.d=good.example/' -e 's/dmarc=fail/dmarc=pass/' "$work/msg.eml" > "$work/msg2.eml"
bash "$S/parse-headers.sh" < "$work/msg2.eml" > "$work/hdr2.md"
has "$work/hdr2.md" "→ aligned with good.example" "dkim aligned"
hasnt "$work/hdr2.md" "Neither SPF nor DKIM" "no fail when dkim aligned"

# ------------------------------------------------ gen-records
o=$work/gen.md
bash "$S/gen-records.sh" -d good.example -i 198.51.100.7 -i 192.0.2.0/28 -I spf.newesp.example -r dmarc@reports.example -k s2026 -s > "$o"
has "$o" '"v=spf1 mx ip4:192.0.2.0/28 include:_spf.esp.example ip4:198.51.100.7 include:spf.newesp.example ~all"' "spf merge, no duplicate"
has "$o" "good.example._report._dmarc.reports.example.  TXT  \"v=DMARC1\"" "external rua record"
has "$o" "p=quarantine; pct=25; rua=mailto:dmarc@reports.example" "staged dmarc"
has "$o" "s2026._domainkey.good.example." "dkim steps"
has "$o" "mx: mail.good.example" "mta-sts policy mx"
bash "$S/gen-records.sh" -d good.example -n -i 198.51.100.7 -q - -p reject > "$work/gen2.md"
has "$work/gen2.md" '"v=spf1 mx ip4:198.51.100.7 -all"' "fresh spf"
has "$work/gen2.md" '"v=DMARC1; p=reject"' "single policy"
bash "$S/gen-records.sh" -d good.example -i '192.0.2.1;rm' > /dev/null 2>&1 && bad "rejects bad ip" || ok
bash "$S/gen-records.sh" -d good.example -r 'a@b.example;x' > /dev/null 2>&1 && bad "rejects bad rua" || ok

echo "passed: $pass, failed: $fail"
[ -n "${KEEP:-}" ] && echo "work dir: $work"
[ "$fail" -eq 0 ]
