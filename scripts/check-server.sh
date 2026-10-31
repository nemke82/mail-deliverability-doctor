#!/usr/bin/env bash
# Read-only check of the local mail server: which MTA, host name and HELO,
# outbound IPs, DKIM signing, queue size, and a summary of recent bounces and
# deferrals from the mail log, grouped by cause (blocklist, authentication,
# reputation, throttling ...). Recipient local parts are masked.
#
# Usage: check-server.sh [-n LINES] [-L LOGFILE]... [-o]
#   -n LINES   analyse the last LINES lines of each log (default 200000)
#   -L FILE    mail log to read (repeatable; '-' for stdin). Default: auto-detect
#   -o         logs only: skip the MTA/queue/DKIM inspection of this machine
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$here/lib.sh"

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
lines=200000; logs=(); logs_only=0
while getopts 'n:L:oh' o; do
  case $o in
    n) [[ $OPTARG =~ ^[0-9]+$ ]] || mdd_die "-n needs a number"; lines=$OPTARG ;;
    L) logs+=("$OPTARG") ;;
    o) logs_only=1 ;;
    h) usage 0 ;;
    *) usage 1 ;;
  esac
done

echo "# Mail server check: $(hostname -f 2>/dev/null || hostname)"
echo
echo "_$(date '+%Y-%m-%d %H:%M %Z')_"

if (( ! logs_only )); then
  echo
  echo "## MTA"
  echo
  mta=none
  if command -v exim >/dev/null 2>&1 || command -v exim4 >/dev/null 2>&1; then
    mta=exim; ex=$(command -v exim || command -v exim4)
    echo "- Exim: $("$ex" -bV 2>/dev/null | head -1)"
    echo "- primary_hostname: $("$ex" -bP primary_hostname 2>/dev/null | cut -d= -f2- | sed 's/^ *//')"
  fi
  if command -v postconf >/dev/null 2>&1; then
    mta=postfix
    echo "- Postfix: $(postconf -h mail_version 2>/dev/null)"
    echo "- myhostname: $(postconf -h myhostname 2>/dev/null)"
    echo "- smtp_helo_name: $(postconf -h smtp_helo_name 2>/dev/null)"
    echo "- smtp_bind_address: $(postconf -h smtp_bind_address 2>/dev/null)"
    echo "- milters: $(postconf -h smtpd_milters 2>/dev/null) / $(postconf -h non_smtpd_milters 2>/dev/null)"
  fi
  [ "$mta" = none ] && echo "- No Exim or Postfix found on this machine."
  panel=none
  [ -d /usr/local/cpanel ] && panel=cpanel
  [ -d /usr/local/psa ] && panel=plesk
  [ -d /usr/local/directadmin ] && panel=directadmin
  echo "- Control panel: $panel"
  echo "- System host name: $(hostname -f 2>/dev/null || hostname)"

  echo
  echo "## Outbound addresses"
  echo
  src4=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -nE 's/.* src ([0-9.]+).*/\1/p')
  src6=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | sed -nE 's/.* src ([0-9a-f:]+).*/\1/p')
  echo "- Default IPv4 source: ${src4:-none}"
  echo "- Default IPv6 source: ${src6:-none}"
  if [ -n "$src4" ] && [[ $src4 =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.) ]]; then
    echo "- The source is private: mail leaves through NAT. Find the public IP (provider panel) and check that one."
  fi
  if [ -n "$src6" ]; then
    echo "- IPv6 is routed: receivers like Gmail will see mail over IPv6 when the MX has AAAA. That IPv6 address needs its own PTR and SPF ip6: entry, or disable IPv6 for outbound SMTP."
  fi
  if [ "$panel" = cpanel ] && [ -s /etc/mailips ]; then
    echo "- cPanel per-domain outbound IPs (/etc/mailips): $(cut -d: -f2- /etc/mailips | tr -d ' ' | sort -u | paste -sd' ' -)"
  fi
  if [ "$panel" = cpanel ] && [ -s /etc/mailhelo ]; then
    echo "- cPanel per-domain HELO names (/etc/mailhelo): $(cut -d: -f2- /etc/mailhelo | tr -d ' ' | sort -u | head -5 | paste -sd' ' -)"
  fi
  echo
  echo "Check each public outbound IP: \`bash scripts/check-ip.sh -H <helo-name> <ip>\`"

  echo
  echo "## DKIM signing"
  echo
  if [ "$panel" = cpanel ]; then
    total=$(cut -d: -f1 /etc/userdomains 2>/dev/null | grep -vc '^\*' || true)
    keys=$(find /var/cpanel/domain_keys/private -maxdepth 1 -type f 2>/dev/null | wc -l)
    echo "- cPanel: $keys DKIM private keys for $total local domains (/var/cpanel/domain_keys/private)."
    echo "  A key on disk signs only if the domain's DNS has the matching default._domainkey record: verify with check-domain.sh."
  elif [ "$mta" = postfix ]; then
    m="$(postconf -h smtpd_milters 2>/dev/null) $(postconf -h non_smtpd_milters 2>/dev/null)"
    if [[ $m =~ [a-z] ]]; then echo "- Postfix milters configured (OpenDKIM/rspamd sign here): $m"
    else echo "- **No milter configured: Postfix is probably not signing with DKIM.**"; fi
  elif [ "$mta" = exim ]; then
    if "$ex" -bP transports 2>/dev/null | grep -q 'dkim_private_key'; then echo "- Exim transport has dkim_private_key set."
    else echo "- Exim: no dkim_private_key option in the transports; DKIM signing may be off."; fi
  fi

  echo
  echo "## Queue"
  echo
  if [ "$mta" = exim ]; then
    q=$("$ex" -bpc 2>/dev/null || echo "?")
    fz=$("$ex" -bp 2>/dev/null | grep -c '\*\*\* frozen \*\*\*' || true)
    echo "- Messages in queue: $q (frozen: $fz)"
    if [[ $q =~ ^[0-9]+$ ]] && (( q > 500 )); then
      echo "- Large queue. Top recipient domains:"
      "$ex" -bp 2>/dev/null | awk 'NF==1 && /@/ {sub(/.*@/,""); print tolower($0)}' | sort | uniq -c | sort -rn | head -10 | sed 's/^/  /'
    fi
  elif [ "$mta" = postfix ]; then
    q=$(postqueue -p 2>/dev/null | tail -1)
    echo "- Queue: ${q:-empty}"
  fi
fi

# ---------------------------------------------------------------- logs
if [ ${#logs[@]} -eq 0 ]; then
  for f in /var/log/exim_mainlog /var/log/exim4/mainlog /var/log/exim/mainlog /var/log/maillog /var/log/mail.log; do
    [ -r "$f" ] && logs+=("$f")
  done
fi
echo
echo "## Bounces and deferrals"
echo
if [ ${#logs[@]} -eq 0 ]; then
  echo "No mail log found. Pass one with -L, or on journald-only systems:"
  echo "\`journalctl -u postfix --since -1d | bash scripts/check-server.sh -o -L -\`"
  exit 0
fi
echo "Logs: ${logs[*]} (last $lines lines each)"

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
for f in "${logs[@]}"; do
  if [ "$f" = - ]; then tail -n "$lines"; else tail -n "$lines" "$f"; fi
done > "$tmp/log"

# Output TSV: kind  recipient-domain  category  normalized-message
awk '
function norm(s) {
  gsub(/[A-Za-z0-9._%+=-]+@[A-Za-z0-9.-]+/, "<addr>", s)
  gsub(/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/, "<ip>", s)
  gsub(/\[[0-9a-fA-F:]+:[0-9a-fA-F:]+\]/, "[<ip6>]", s)
  gsub(/[A-Za-z0-9_-]{24,}/, "<id>", s)
  gsub(/[ \t]+/, " ", s)
  return substr(s, 1, 200)
}
function cat(s,   l) {
  l = tolower(s)
  if (l ~ /s3140|s3150|sender\.office\.com/) return "microsoft-blocklist"
  if (l ~ /5\.7\.606|5\.7\.511|banned sending ip|banned sender/) return "microsoft-banned"
  if (l ~ /5\.7\.515|required authentication level/) return "microsoft-auth"
  if (l ~ /hm0[0-9]|icloud\.com|mail\.me\.com|me\.com.*(policy|reject)/ && l ~ /policy|reject|blocked|hm0/) return "apple-policy"
  if (l ~ /5\.7\.26|unauthenticated|dmarc/) return "auth-dmarc"
  if (l ~ /5\.7\.27/) return "auth-spf"
  if (l ~ /5\.7\.25|reverse dns|ptr record|rdns|reverse lookup|does not have a ptr/) return "ptr"
  if (l ~ /4\.7\.28|5\.7\.28|unusual rate/) return "gmail-rate"
  if (l ~ /likely unsolicited|very low reputation|low reputation|poor reputation|bad reputation/) return "reputation"
  if (l ~ /tss04/) return "yahoo-deferral"
  if (l ~ /tss09|tss05/) return "yahoo-block"
  if (l ~ /spamhaus|barracuda|spamcop|blocked using|blacklist|blocklist|listed (at|on|in|by)|[^a-z]rbl[^a-z]|dnsbl|uceprotect/) return "dnsbl"
  if (l ~ /spf/) return "auth-spf"
  if (l ~ /dkim/) return "auth-dkim"
  if (l ~ /5\.1\.1|user unknown|unknown user|does not exist|no such user|mailbox unavailable|recipient not found|invalid recipient|unrouteable|address rejected/) return "bad-recipient"
  if (l ~ /5\.2\.2|mailbox full|over quota|quota exceeded|insufficient storage/) return "mailbox-full"
  if (l ~ /5\.7\.[0-9]+.*(spam|content)|message content|spam/) return "content-spam"
  if (l ~ /starttls|tls|certificate|handshake/) return "tls"
  if (l ~ /connection timed out|connection refused|network is unreachable|no route to host|retry timeout exceeded|all hosts .* have been failing|no answer|connection reset/) return "connection"
  if (l ~ /too many|throttl|rate limit|try again later|temporarily deferred|temporarily rejected|^4[0-9][0-9]|[ :]4[0-9][0-9][ -]/) return "throttled"
  return "other"
}
# Exim: "** addr ..." (bounce) and "== addr ..." (deferral)
/ (\*\*|==) [^ ]+/ {
  kind = (index($0, " ** ") ? "bounce" : "defer")
  rest = $0; i = index(rest, (kind == "bounce" ? " ** " : " == ")); rest = substr(rest, i + 4)
  split(rest, w, " "); rcpt = w[1]
  if (rcpt !~ /@/) next
  d = rcpt; sub(/.*@/, "", d); sub(/[>:,]+$/, "", d)
  m = $0
  if (match(m, /remote mail server after /)) {
    m = substr(m, RSTART + RLENGTH)
    sub(/^(RCPT TO|MAIL FROM):<[^>]*>: /, "", m); sub(/^[A-Za-z ]+: /, "", m)
  } else {
    n = split(m, p, ": "); m = p[n]
  }
  print kind "\t" tolower(d) "\t" cat(m) "\t" norm(m)
  next
}
# Postfix: "to=<addr>, ... status=bounced (text)" / status=deferred
/ to=<[^>]*@[^>]*>.* status=(bounced|deferred) / {
  kind = ($0 ~ /status=bounced/) ? "bounce" : "defer"
  match($0, /to=<[^>]*>/); rcpt = substr($0, RSTART + 4, RLENGTH - 5)
  d = rcpt; sub(/.*@/, "", d)
  m = $0; i = index(m, "status=" (kind == "bounce" ? "bounced" : "deferred") " ("); m = substr(m, i)
  sub(/^status=[a-z]+ \(/, "", m); sub(/\)$/, "", m)
  sub(/^host [^ ]+ said: /, "", m); sub(/ \(in reply to [^)]*\)$/, "", m)
  print kind "\t" tolower(d) "\t" cat(m) "\t" norm(m)
}
' "$tmp/log" > "$tmp/events"

total=$(wc -l < "$tmp/events")
b=$(awk -F'\t' '$1=="bounce"' "$tmp/events" | wc -l)
echo
echo "Found $total failed delivery attempts: $b bounces, $((total - b)) deferrals."
if (( total > 0 )); then
  echo
  echo "### By cause"
  echo
  echo "| Cause | Attempts | Bounces | Top recipient domains | Example reply |"
  echo "|---|---|---|---|---|"
  awk -F'\t' '
    { n[$3]++; if ($1=="bounce") bo[$3]++; dc[$3 SUBSEP $2]++; if (!($3 in ex)) ex[$3]=$4 }
    END {
      for (c in n) {
        top=""
        # pick up to 3 domains with most events for this cause
        for (k = 0; k < 3; k++) {
          best=""; bv=0
          for (key in dc) { split(key, kk, SUBSEP); if (kk[1]==c && dc[key]>bv && !(key in used)) { bv=dc[key]; best=key } }
          if (best=="") break
          used[best]=1; split(best, kk, SUBSEP); top = top (top=="" ? "" : ", ") kk[2] " (" bv ")"
        }
        e = ex[c]; gsub(/\|/, "/", e)
        printf "%d\t| %s | %d | %d | %s | %s |\n", n[c], c, n[c], bo[c]+0, top, e
      }
    }' "$tmp/events" | sort -t$'\t' -k1,1nr | cut -f2-
  echo
  echo "### By recipient domain"
  echo
  echo "| Domain | Attempts | Main cause |"
  echo "|---|---|---|"
  awk -F'\t' '{ n[$2]++; c[$2 SUBSEP $3]++ }
    END { for (d in n) { best=""; bv=0; for (k in c) { split(k, kk, SUBSEP); if (kk[1]==d && c[k]>bv) { bv=c[k]; best=kk[2] } }
          printf "%d\t| %s | %d | %s |\n", n[d], d, n[d], best } }' "$tmp/events" |
    sort -t$'\t' -k1,1nr | head -15 | cut -f2-
  echo
  echo "What each cause means and how to fix it: references/provider-codes.md."
fi

# Outbound volume per authenticated user / script (spotting a compromised account)
echo
echo "### Top senders in the log window"
echo
awk '
  / <= / && match($0, / A=[a-z_]+:[^ ]+/) { s = substr($0, RSTART + 3, RLENGTH - 3); sub(/^[a-z_]+:/, "", s); a["auth " s]++ }
  / <= / && match($0, / U=[^ ]+ P=local/) { s = substr($0, RSTART + 3, RLENGTH - 3); sub(/ P=local$/, "", s); a["local user " s]++ }
  /cwd=\/home\/[^ ]+/ && match($0, /cwd=\/home\/[^ ]+/) { s = substr($0, RSTART + 4, RLENGTH - 4); a["script dir " s]++ }
  /sasl_username=/ && match($0, /sasl_username=[^ ,]+/) { s = substr($0, RSTART + 14, RLENGTH - 14); a["auth " s]++ }
  END { for (k in a) printf "%d\t%s\n", a[k], k }' "$tmp/log" | sort -rn | head -10 |
  awk -F'\t' 'BEGIN { print "| Messages | Sender |"; print "|---|---|" } { printf "| %s | %s |\n", $1, $2 } END { if (NR == 0) print "| - | no authenticated or local senders found in this log format |" }'
echo
echo "One mailbox or script sending far more than the rest usually means stolen"
echo "credentials or an exploited form: stop it before requesting any delisting."
exit 0
