#!/usr/bin/env bash
# Read-only reputation check of a sending IP: reverse DNS (PTR) with forward
# confirmation, generic-hostname detection, HELO consistency and public DNS
# blocklists. Prints a markdown report.
#
# Usage: check-ip.sh [-H HELO_NAME] IP [IP...]
#   -H NAME   the name the server announces in HELO/EHLO (checked against PTR and DNS)
#
# Spamhaus refuses queries that arrive through big public resolvers (8.8.8.8,
# 1.1.1.1 ...). Run this from the mail server or set MDD_RESOLVER to a resolver
# you run yourself; refused answers are reported, never counted as listings.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$here/lib.sh"

usage() { sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

helo=""
while getopts 'H:h' o; do
  case $o in
    H) helo=${OPTARG,,}; helo=${helo%.}; mdd_is_domain "$helo" || mdd_die "HELO name is not a fully qualified domain name: $OPTARG" ;;
    h) usage 0 ;;
    *) usage 1 ;;
  esac
done
shift $((OPTIND - 1))
[ $# -ge 1 ] || usage 1
for ip in "$@"; do mdd_is_ipv4 "$ip" || mdd_is_ipv6 "$ip" || mdd_die "not an IP address: $ip"; done
mdd_need_dig

# zone|weight|IPv6 support|delisting page
lists=(
  "zen.spamhaus.org|high|yes|https://check.spamhaus.org/"
  "b.barracudacentral.org|high|no|https://www.barracudacentral.org/rbl/removal-request"
  "bl.spamcop.net|high|no|https://www.spamcop.net/bl.shtml"
  "psbl.surriel.com|medium|no|https://psbl.org/"
  "bl.mailspike.net|medium|no|https://mailspike.org/"
  "ix.dnsbl.manitu.net|medium|no|https://www.nixspam.net/"
  "dnsbl.dronebl.org|medium|no|https://dronebl.org/lookup"
  "dnsbl-1.uceprotect.net|low|no|https://www.uceprotect.net/en/rblcheck.php"
)

spamhaus_code() {
  case $1 in
    127.0.0.2) echo "SBL (spam source)" ;;
    127.0.0.3) echo "SBL CSS (snowshoe/low reputation)" ;;
    127.0.0.4|127.0.0.5|127.0.0.6|127.0.0.7) echo "XBL (infected or exploited host)" ;;
    127.0.0.9) echo "DROP (hijacked network)" ;;
    127.0.0.10) echo "PBL ISP (end-user range, should not send directly)" ;;
    127.0.0.11) echo "PBL Spamhaus (end-user range, should not send directly)" ;;
    *) echo "$1" ;;
  esac
}

sev=(); msg=()
add() { sev+=("$1"); msg+=("$2"); }

echo "# Sending IP check"
echo
echo "_$(date -u '+%Y-%m-%d %H:%M UTC')${MDD_RESOLVER:+, resolver $MDD_RESOLVER}_"

for ip in "$@"; do
  echo
  echo "## $ip"
  echo
  # ------------------------------------------------ reverse DNS
  ptrs=$(mdd_dns PTR "$(mdd_ptr_name "$ip")" | sed 's/\.$//')
  if [ -z "$ptrs" ]; then
    echo "- PTR: **none**"
    add FAIL "$ip has no reverse DNS (PTR). Gmail, Microsoft and most receivers reject or junk mail from such IPs. Ask whoever owns the IP (hosting provider) to set a PTR to the server's mail host name."
  else
    (( $(grep -c . <<< "$ptrs") > 1 )) && add WARN "$ip has several PTR records; use exactly one."
    while read -r p; do
      fwd=$(mdd_addrs "$p")
      if grep -qixF "$ip" <<< "$fwd"; then fc="forward-confirmed"
      else
        fc="**does not resolve back to $ip**"
        add FAIL "PTR $p for $ip does not resolve back to $ip (no forward-confirmed reverse DNS). Add an A/AAAA record $p -> $ip."
      fi
      echo "- PTR: $p ($fc)"
      oct=${ip//[.:]/[.-]}
      if [[ ${p,,} =~ $oct || ${p,,} =~ (^|[.-])(dynamic|dyn|dhcp|pool|dsl|adsl|cable|broadband|ppp|dialup|customer|client|unassigned|static-ip|ip-[0-9]|host-[0-9]|vps-[0-9]) ]]; then
        add WARN "PTR $p looks generic (IP digits or ISP pool words). Receivers score these as residential/unmanaged; use a name like mail.yourdomain."
      fi
    done <<< "$ptrs"
  fi

  # ------------------------------------------------ HELO
  if [ -n "$helo" ]; then
    hfwd=$(mdd_addrs "$helo")
    if [ -z "$hfwd" ]; then
      echo "- HELO $helo: **does not resolve**"
      add FAIL "HELO name $helo does not resolve. Many receivers reject a HELO that is not a resolvable FQDN."
    elif ! grep -qixF "$ip" <<< "$hfwd"; then
      echo "- HELO $helo: resolves to $(tr '\n' ' ' <<< "$hfwd")(not $ip)"
      add WARN "HELO name $helo does not resolve to $ip. Set the server's HELO to its PTR name."
    else
      echo "- HELO $helo: resolves to $ip"
    fi
    if [ -n "$ptrs" ] && ! grep -qixF "$helo" <<< "$ptrs"; then
      add INFO "HELO $helo differs from the PTR ($(head -1 <<< "$ptrs")). Not an error, but matching names avoid spam-filter points."
    fi
    hspf=$(mdd_dns TXT "$helo" | grep -iE '^v=spf1( |$)' || true)
    [ -z "$hspf" ] && add INFO "HELO name $helo has no SPF record. Bounces and DSNs are checked against it; publish \"v=spf1 a -all\" on $helo."
  fi

  # ------------------------------------------------ blocklists
  echo
  echo "| Blocklist | Weight | Result | Delisting |"
  echo "|---|---|---|---|"
  for l in "${lists[@]}"; do
    IFS='|' read -r zone weight v6 url <<< "$l"
    if mdd_is_ipv6 "$ip" && [ "$v6" != yes ]; then continue; fi
    ans=$(mdd_dns A "$(mdd_rev "$ip").$zone" | sort -u)
    if [ -z "$ans" ]; then
      res="not listed"
    elif grep -q '^127\.255\.255\.' <<< "$ans" || grep -qvE '^127\.' <<< "$ans"; then
      res="query refused ($(tr '\n' ' ' <<< "$ans" | sed 's/ $//')): use your own resolver"
      add INFO "$zone refused the query (answer $(head -1 <<< "$ans")). Re-run from the mail server or with MDD_RESOLVER pointing to a non-public resolver."
    else
      if [ "$zone" = zen.spamhaus.org ]; then
        res="**listed**: $(while read -r a; do spamhaus_code "$a"; done <<< "$ans" | paste -sd, -)"
      else
        res="**listed** ($(paste -sd, - <<< "$ans"))"
      fi
      why=$(mdd_dns TXT "$(mdd_rev "$ip").$zone" | head -1)
      [ -n "$why" ] && res+=" — ${why:0:120}"
      case $weight in
        high)   add FAIL "$ip is listed on $zone. Fix the cause first (compromised account, open relay, infected script), then request removal: $url" ;;
        medium) add WARN "$ip is listed on $zone. Fix the cause, then request removal: $url" ;;
        low)    add INFO "$ip is listed on $zone (few large receivers use it). $url" ;;
      esac
    fi
    echo "| $zone | $weight | $res | $url |"
  done
done

echo
echo "Microsoft (Outlook/Hotmail), Apple iCloud, Gmail and Yahoo use their own"
echo "reputation data, not these lists. An IP can be clean here and still blocked"
echo "there; check their bounce codes with check-server.sh and references/provider-codes.md."

echo
echo "## Findings"
echo
n=0
for want in FAIL WARN INFO; do
  for i in "${!sev[@]}"; do
    [ "${sev[i]}" = "$want" ] || continue
    echo "- **$want** ${msg[i]}"
    n=$((n + 1))
  done
done
(( n == 0 )) && echo "- **OK** Reverse DNS is correct and the IP is on none of the checked blocklists."
exit 0
