#!/usr/bin/env bash
# Print (never publish) corrected DNS records for a sending domain: an SPF
# record merged with the current one, a staged DMARC rollout, DKIM key
# generation steps, and optional MTA-STS / TLS-RPT records.
#
# Usage: gen-records.sh -d DOMAIN [options]
#   -i IP        authorize this sending IP in SPF (repeatable, IPv4/IPv6, CIDR ok)
#   -I DOMAIN    add include:DOMAIN to SPF, e.g. an ESP (repeatable)
#   -q ~|-       'all' qualifier: ~ softfail (default) or - fail
#   -n           build SPF from scratch instead of merging the published record
#   -r ADDRESS   DMARC aggregate-report mailbox (rua)
#   -p POLICY    print only this DMARC policy (none|quarantine|reject) instead of the staged plan
#   -k SELECTOR  print DKIM key generation and publishing steps for SELECTOR
#   -s           print MTA-STS and TLS-RPT records and the policy file
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$here/lib.sh"

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
domain=""; ips=(); incs=(); qual='~'; fresh=0; rua=""; policy=""; sel=""; sts=0
while getopts 'd:i:I:q:nr:p:k:sh' o; do
  case $o in
    d) domain=${OPTARG,,}; domain=${domain%.} ;;
    i) v=${OPTARG%/*}; b=""; [[ $OPTARG == */* ]] && b=${OPTARG#*/}
       if mdd_is_ipv4 "$v"; then [[ -z $b || ( $b =~ ^[0-9]{1,2}$ && $b -ge 8 && $b -le 32 ) ]] || mdd_die "bad IPv4 prefix: $OPTARG"
       elif mdd_is_ipv6 "$v"; then [[ -z $b || ( $b =~ ^[0-9]{1,3}$ && $b -ge 32 && $b -le 128 ) ]] || mdd_die "bad IPv6 prefix: $OPTARG"
       else mdd_die "not an IP address: $OPTARG"; fi
       ips+=("$OPTARG") ;;
    I) mdd_is_domain "$OPTARG" || mdd_die "not a domain: $OPTARG"; incs+=("${OPTARG,,}") ;;
    q) [[ $OPTARG == '~' || $OPTARG == - ]] || mdd_die "-q takes ~ or -"; qual=$OPTARG ;;
    n) fresh=1 ;;
    r) [[ $OPTARG =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || mdd_die "not an e-mail address: $OPTARG"; rua=$OPTARG ;;
    p) [[ $OPTARG =~ ^(none|quarantine|reject)$ ]] || mdd_die "policy must be none, quarantine or reject"; policy=$OPTARG ;;
    k) [[ $OPTARG =~ ^[A-Za-z0-9-]{1,63}$ ]] || mdd_die "bad selector: $OPTARG"; sel=$OPTARG ;;
    s) sts=1 ;;
    h) usage 0 ;;
    *) usage 1 ;;
  esac
done
[ -n "$domain" ] || usage 1
mdd_is_domain "$domain" || mdd_die "not a domain: $domain"
mdd_need_dig

echo "# Proposed DNS records for $domain"
echo
echo "Nothing has been published. Review each record, then add it in the DNS"
echo "provider (or control panel) that hosts $domain. Lower the TTL first if you"
echo "may need to roll back quickly."

# ---------------------------------------------------------------- SPF
echo
echo "## SPF"
echo
cur=""
(( fresh )) || cur=$(mdd_dns TXT "$domain" | grep -iE '^v=spf1( |$)' | head -1 || true)
terms=(); redirect=""
if [ -n "$cur" ]; then
  echo "Current: \`$cur\`"
  read -r -a t <<< "$cur"
  for x in "${t[@]:1}"; do
    case ${x,,} in
      [-+~?]all|all) ;;
      redirect=*) redirect=$x ;;
      *) terms+=("$x") ;;
    esac
  done
else
  echo "Current: none (building a new record)"
  terms=(mx)
fi
has() { local x; for x in "${terms[@]}"; do [ "${x,,}" = "${1,,}" ] && return 0; done; return 1; }
for ip in "${ips[@]}"; do
  if [[ $ip == *:* ]]; then term="ip6:$ip"; else term="ip4:$ip"; fi
  has "$term" || has "${term%/32}" || terms+=("$term")
done
for d in "${incs[@]}"; do has "include:$d" || terms+=("include:$d"); done

lookups=0
for x in "${terms[@]}" ${redirect:+"$redirect"}; do
  case ${x,,} in [-+~?]*) x=${x:1} ;; esac
  case ${x,,} in include:*|a|a:*|a/*|mx|mx:*|mx/*|ptr|ptr:*|exists:*|redirect=*) lookups=$((lookups + 1)) ;; esac
done
if [ -n "$redirect" ]; then new="v=spf1 ${terms[*]} $redirect"
else new="v=spf1 ${terms[*]} ${qual}all"; fi
new=$(tr -s ' ' <<< "$new")
echo
echo "Proposed:"
echo
echo '```'
echo "$domain.  TXT  \"$new\""
echo '```'
echo
echo "Top-level lookups: $lookups (nested includes add more; the limit is 10 in total)."
echo "Verify after publishing: \`bash scripts/check-domain.sh${ips[*]:+ -i ${ips[0]%/*}} $domain\`"
(( ${#new} > 255 )) && echo "The record is over 255 characters: enter it as several quoted strings, e.g. \"first part\" \"second part\" (most DNS panels split it automatically)."
[ -n "$redirect" ] && echo "The current record ends in $redirect, which was kept; the 'all' qualifier then comes from the redirected record."
echo "Keep exactly one SPF record: replace the old one, do not add a second."

# ---------------------------------------------------------------- DMARC
echo
echo "## DMARC"
echo
ruat=""; [ -n "$rua" ] && ruat="; rua=mailto:$rua"
if [ -n "$rua" ]; then
  rdom=${rua##*@}; rdom=${rdom,,}
  if [ "$(mdd_org_domain "$rdom")" != "$(mdd_org_domain "$domain")" ]; then
    echo "Reports go to another domain, so $rdom must allow it with this record:"
    echo
    echo '```'
    echo "$domain._report._dmarc.$rdom.  TXT  \"v=DMARC1\""
    echo '```'
    echo
  fi
fi
if [ -n "$policy" ]; then
  echo '```'
  echo "_dmarc.$domain.  TXT  \"v=DMARC1; p=$policy$ruat\""
  echo '```'
else
  cat <<EOF
Roll out in stages; move on only when the aggregate reports show that every
legitimate sender (servers, ESPs, CRM, invoicing tools) passes aligned SPF or DKIM.

1. Monitor (now, 2 to 4 weeks):

   \`\`\`
   _dmarc.$domain.  TXT  "v=DMARC1; p=none$ruat"
   \`\`\`

2. Quarantine part of the failures, then all of them:

   \`\`\`
   _dmarc.$domain.  TXT  "v=DMARC1; p=quarantine; pct=25$ruat"
   _dmarc.$domain.  TXT  "v=DMARC1; p=quarantine$ruat"
   \`\`\`

3. Reject:

   \`\`\`
   _dmarc.$domain.  TXT  "v=DMARC1; p=reject$ruat"
   \`\`\`
EOF
  [ -z "$rua" ] && echo && echo "Add -r ADDRESS to include a report mailbox; without reports the rollout is blind."
fi

# ---------------------------------------------------------------- DKIM
if [ -n "$sel" ]; then
  cat <<EOF

## DKIM (selector $sel)

If a control panel or ESP manages the domain, generate the key there instead
(cPanel: Email Deliverability; Plesk: Mail Settings > DKIM; Microsoft 365 and
Google Workspace: admin console) and publish the record it shows.

Otherwise, on the mail server:

\`\`\`sh
umask 077
openssl genrsa -out $sel.$domain.key 2048
openssl rsa -in $sel.$domain.key -pubout -outform DER 2>/dev/null | openssl base64 -A; echo
\`\`\`

Publish the printed key (one line) as:

\`\`\`
$sel._domainkey.$domain.  TXT  "v=DKIM1; k=rsa; p=<printed key>"
\`\`\`

Configure the signer (OpenDKIM KeyTable/SigningTable, rspamd dkim_signing,
or Exim dkim_private_key) with the private key and selector $sel, then check
with \`bash scripts/check-domain.sh -s $sel $domain\` and a test message through
\`parse-headers.sh\`. Keep the old selector published until mail signed with
it has stopped arriving (a few days).
EOF
fi

# ---------------------------------------------------------------- MTA-STS / TLS-RPT
if (( sts )); then
  mxl=$(mdd_dns MX "$domain" | awk '{print $2}' | sed 's/\.$//')
  id=$(date -u +%Y%m%d%H%M)
  echo
  echo "## MTA-STS and TLS-RPT"
  echo
  echo "Start in testing mode; switch to enforce after a few weeks of clean TLS reports."
  echo
  echo '```'
  echo "_mta-sts.$domain.   TXT  \"v=STSv1; id=$id\""
  echo "_smtp._tls.$domain. TXT  \"v=TLSRPTv1; rua=mailto:${rua:-tls-reports@$domain}\""
  echo "mta-sts.$domain.    A/CNAME  -> a web server with a valid HTTPS certificate for mta-sts.$domain"
  echo '```'
  echo
  echo "Serve this at https://mta-sts.$domain/.well-known/mta-sts.txt:"
  echo
  echo '```'
  echo "version: STSv1"
  echo "mode: testing"
  if [ -n "$mxl" ]; then while read -r m; do echo "mx: $m"; done <<< "$mxl"; else echo "mx: <your MX host>"; fi
  echo "max_age: 604800"
  echo '```'
  echo
  echo "Change the id= value every time the policy file changes."
fi
exit 0
