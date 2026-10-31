#!/usr/bin/env bash
# Read-only DNS audit of a sending domain: MX, SPF (with lookup count and
# optional IP evaluation), DKIM, DMARC (with external report authorization),
# MTA-STS, TLS-RPT and BIMI. Prints a markdown report.
#
# Usage: check-domain.sh [-i SENDING_IP]... [-s DKIM_SELECTOR]... [-t] DOMAIN
#   -i IP     evaluate SPF for this sending IPv4 address (repeatable)
#   -s SEL    DKIM selector to check (repeatable); default probes common selectors
#   -t        also test STARTTLS on each MX (needs outbound port 25)
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$here/lib.sh"

usage() { sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

ips=(); sels=(); test_mx=0
while getopts 'i:s:th' o; do
  case $o in
    i) mdd_is_ipv4 "$OPTARG" || mdd_is_ipv6 "$OPTARG" || mdd_die "not an IP address: $OPTARG"; ips+=("$OPTARG") ;;
    s) [[ $OPTARG =~ ^[A-Za-z0-9._-]{1,63}$ ]] || mdd_die "bad selector: $OPTARG"; sels+=("$OPTARG") ;;
    t) test_mx=1 ;;
    h) usage 0 ;;
    *) usage 1 ;;
  esac
done
shift $((OPTIND - 1))
[ $# -eq 1 ] || usage 1
domain=${1,,}; domain=${domain%.}
mdd_is_domain "$domain" || mdd_die "not a domain name: $1"
mdd_need_dig

sev=(); msg=()
add() { sev+=("$1"); msg+=("$2"); }

echo "# Mail deliverability: $domain"
echo
echo "_$(date -u '+%Y-%m-%d %H:%M UTC')${MDD_RESOLVER:+, resolver $MDD_RESOLVER}_"

# ---------------------------------------------------------------- MX
echo
echo "## MX"
echo
mx=$(mdd_dns MX "$domain" | sort -n)
if [ -z "$mx" ]; then
  a=$(mdd_addrs "$domain")
  if [ -n "$a" ]; then
    echo "No MX record; mail falls back to the domain's own address ($(tr '\n' ' ' <<< "$a"))."
    add WARN "No MX record: mail for $domain goes to the A record. Publish an MX (or a null MX \"0 .\" if the domain never receives mail)."
  else
    echo "No MX and no address record."
    add FAIL "$domain has no MX and no A/AAAA record: nobody can reply or bounce to it, and many receivers reject such senders."
  fi
  mxhosts=()
else
  echo "| Pref | Host | Addresses | Note |"
  echo "|---|---|---|---|"
  mxhosts=()
  while read -r pref host; do
    host=${host%.}
    if [ "$host" = "" ] || [ "$host" = "." ]; then
      echo "| $pref | . | | null MX: domain does not receive mail |"
      add INFO "Null MX: $domain declares that it receives no mail. Fine for send-only domains, but bounces and replies are lost."
      continue
    fi
    mxhosts+=("$host")
    note=""; addr=""
    if mdd_is_ipv4 "$host" || mdd_is_ipv6 "$host"; then
      note="MX points to an IP address (invalid)"
      add FAIL "MX $host is an IP address; an MX must be a host name."
    else
      addr=$(mdd_addrs "$host" | tr '\n' ' ')
      [ -n "$(mdd_dns CNAME "$host")" ] && { note="CNAME (not allowed for MX targets)"; add WARN "MX host $host is a CNAME; RFC 5321 requires the MX target to have its own A/AAAA."; }
      [ -z "$addr" ] && { note="does not resolve"; add FAIL "MX host $host does not resolve to any address."; }
    fi
    echo "| $pref | $host | ${addr:-} | $note |"
  done <<< "$mx"
fi

# ---------------------------------------------------------------- SPF
spf_get() { mdd_dns TXT "$1" | grep -iE '^v=spf1( |$)' || true; }

declare -A spf_seen=()
spf_lookups=0; spf_void=0; spf_lines=(); spf_problems=()

# Walk the whole include tree, counting DNS-querying terms (RFC 7208 limit 10)
# and void lookups (limit 2).
spf_walk() {
  local dom=$1 depth=$2 recs n rec term mech rest target q ind
  local -a terms
  ind=$(printf '%*s' $((depth * 2)) '')
  if (( depth > 10 )); then spf_lines+=("$ind- (stopped: nested too deep)"); return; fi
  if [ -n "${spf_seen[$dom]:-}" ]; then spf_lines+=("$ind- $dom (already counted, loop?)"); spf_problems+=("include loop or repeated include of $dom"); return; fi
  spf_seen[$dom]=1
  recs=$(spf_get "$dom")
  n=$(grep -c . <<< "$recs")
  if (( n == 0 )); then
    spf_lines+=("$ind- $dom: **no SPF record**")
    (( depth > 0 )) && spf_problems+=("included domain $dom has no SPF record (permerror)")
    return
  fi
  (( n > 1 )) && spf_problems+=("$dom has $n SPF records (permerror: must be exactly one)")
  rec=$(head -1 <<< "$recs")
  spf_lines+=("$ind- $dom: \`$rec\`")
  read -r -a terms <<< "$rec"
  for term in "${terms[@]:1}"; do
    q=${term:0:1}; [[ $q == [-+~?] ]] && term=${term:1}
    mech=${term%%[:=/]*}; mech=${mech,,}
    rest=${term#"$mech"}; rest=${rest#[:=]}
    target=${rest%%/*}
    case $mech in
      include|redirect)
        spf_lookups=$((spf_lookups + 1))
        if [[ $target == *%* ]]; then spf_lines+=("$ind  - $target (macro, not expanded)"); continue; fi
        spf_walk "${target,,}" $((depth + 1)) ;;
      a|mx|exists|ptr)
        spf_lookups=$((spf_lookups + 1))
        [ "$mech" = ptr ] && spf_problems+=("$dom uses the deprecated ptr mechanism (slow, many receivers ignore it)")
        [[ $target == *%* ]] && continue
        [ -z "$target" ] && target=$dom
        if [ "$mech" = mx ]; then
          local mxl; mxl=$(mdd_dns MX "$target")
          [ -z "$mxl" ] && spf_void=$((spf_void + 1))
          (( $(grep -c . <<< "$mxl") > 10 )) && spf_problems+=("mx:$target has more than 10 MX hosts (permerror)")
        elif [ "$mech" != ptr ]; then
          [ -z "$(mdd_addrs "$target")" ] && spf_void=$((spf_void + 1))
        fi ;;
      ip4|ip6|all|exp|v) ;;
      *) spf_problems+=("$dom has an unknown SPF term '$term' (permerror)") ;;
    esac
  done
}

# Evaluate SPF for an IPv4 address. Prints pass|fail|softfail|neutral|none|permerror|unknown.
spf_eval() {
  local dom=$1 ip=$2 depth=$3 recs rec term q mech rest target cidr redirect="" r h match
  local -a terms
  (( depth > 10 )) && { echo permerror; return; }
  recs=$(spf_get "$dom")
  [ -z "$recs" ] && { echo none; return; }
  (( $(grep -c . <<< "$recs") > 1 )) && { echo permerror; return; }
  rec=$recs
  read -r -a terms <<< "$rec"
  for term in "${terms[@]:1}"; do
    q=+; [[ ${term:0:1} == [-+~?] ]] && { q=${term:0:1}; term=${term:1}; }
    mech=${term%%[:=/]*}; mech=${mech,,}
    rest=${term#"$mech"}; rest=${rest#[:=]}
    target=${rest%%/*}
    cidr=${rest#"$target"}; cidr=${cidr#/}; cidr=${cidr%%/*}; [ -z "$cidr" ] && cidr=32
    [[ $target == *%* ]] && { echo unknown; return; }
    match=0
    case $mech in
      all) match=1 ;;
      ip4) mdd_in_cidr "$ip" "$rest" && match=1 ;;
      ip6) ;;
      a)
        for h in $(mdd_dns A "${target:-$dom}"); do mdd_in_cidr "$ip" "$h/$cidr" && { match=1; break; }; done ;;
      mx)
        for h in $(mdd_dns MX "${target:-$dom}" | awk '{print $2}'); do
          for r in $(mdd_dns A "$h"); do mdd_in_cidr "$ip" "$r/$cidr" && { match=1; break 2; }; done
        done ;;
      ptr)
        for h in $(mdd_dns PTR "$(mdd_ptr_name "$ip")"); do
          h=${h%.}
          if [[ ${h,,} == "${target:-$dom}" || ${h,,} == *."${target:-$dom}" ]] && mdd_dns A "$h" | grep -qxF "$ip"; then match=1; break; fi
        done ;;
      exists) [ -n "$(mdd_dns A "$target")" ] && match=1 ;;
      include)
        r=$(spf_eval "${target,,}" "$ip" $((depth + 1)))
        case $r in
          pass) match=1 ;;
          none|permerror) echo permerror; return ;;
          unknown) echo unknown; return ;;
        esac ;;
      redirect) redirect=${target,,}; continue ;;
      exp|v) continue ;;
      *) echo permerror; return ;;
    esac
    if (( match )); then
      case $q in +) echo pass ;; -) echo fail ;; '~') echo softfail ;; '?') echo neutral ;; esac
      return
    fi
  done
  if [ -n "$redirect" ]; then
    r=$(spf_eval "$redirect" "$ip" $((depth + 1)))
    [ "$r" = none ] && r=permerror
    echo "$r"; return
  fi
  echo neutral
}

echo
echo "## SPF"
echo
spf=$(spf_get "$domain")
if [ -z "$spf" ]; then
  echo "No SPF record."
  add FAIL "No SPF record on $domain. Gmail, Yahoo and Microsoft require SPF or DKIM for all senders and both for bulk senders."
else
  spf_walk "$domain" 0
  printf '%s\n' "${spf_lines[@]}"
  echo
  echo "DNS-querying terms: **$spf_lookups** of 10 allowed; void lookups: $spf_void of 2 allowed."
  if (( spf_lookups > 10 )); then
    add FAIL "SPF needs $spf_lookups DNS lookups (limit 10): receivers return permerror and treat SPF as failed. Remove unused includes or replace them with ip4/ip6 ranges."
  elif (( spf_lookups >= 9 )); then
    add WARN "SPF uses $spf_lookups of 10 DNS lookups; one more include from a provider will break it."
  fi
  (( spf_void > 2 )) && add FAIL "SPF has $spf_void void lookups (names that do not resolve; limit 2): permerror."
  for p in "${spf_problems[@]}"; do
    case $p in *deprecated*) add WARN "SPF: $p." ;; *) add FAIL "SPF: $p." ;; esac
  done
  top=$(head -1 <<< "$spf")
  case " ${top,,} " in
    *" +all "*|*" all "*) add FAIL "SPF ends in +all: any server on the internet passes SPF for $domain. Use ~all or -all." ;;
    *" ?all "*) add WARN "SPF ends in ?all (neutral): it authorizes nothing. Use ~all or -all." ;;
    *" ~all "*|*" -all "*) ;;
    *) [[ ${top,,} == *redirect=* ]] || add WARN "SPF has no 'all' term and no redirect: unlisted senders get neutral. End it with ~all or -all." ;;
  esac
  (( ${#top} > 450 )) && add WARN "SPF record is ${#top} characters; long records risk DNS truncation and must be split into 255-character strings."
fi

if [ ${#ips[@]} -gt 0 ]; then
  echo
  echo "### SPF result for sending IPs"
  echo
  echo "| IP | Result |"
  echo "|---|---|"
  for ip in "${ips[@]}"; do
    if mdd_is_ipv6 "$ip"; then
      r="not evaluated (IPv6: compare with the ip6: terms by hand)"
    else
      r=$(spf_eval "$domain" "$ip" 0)
      case $r in
        pass) ;;
        unknown) add INFO "SPF for $ip could not be evaluated offline (macros in the record)." ;;
        none) ;;
        *) add FAIL "Sending IP $ip gets SPF '$r' for $domain: add ip4:$ip (or the provider's include) to the SPF record." ;;
      esac
    fi
    echo "| $ip | $r |"
  done
fi

# ---------------------------------------------------------------- DKIM
echo
echo "## DKIM"
echo
probe=0
if [ ${#sels[@]} -eq 0 ]; then
  probe=1
  sels=(default dkim mail selector1 selector2 google k1 k2 k3 s1 s2 smtp mx key1 key2 dkim1 mandrill mailjet zoho zmail sig1 fm1 fm2 fm3 protonmail protonmail2 protonmail3 pm krs mta x everlytickey1 cm 2024 2025 2026)
fi
found=0
for s in "${sels[@]}"; do
  name="$s._domainkey.$domain"
  rec=$(mdd_dns TXT "$name" | grep -iE '(^|;)[[:space:]]*(v=DKIM1|p=)' | head -1)
  if [ -z "$rec" ]; then
    (( probe )) || { echo "- \`$s\`: no DKIM key at $name"; add FAIL "DKIM selector '$s' has no key published at $name: signatures with s=$s fail."; }
    continue
  fi
  found=$((found + 1))
  p=$(sed -nE 's/.*(^|;)[[:space:]]*p=([^;]*).*/\2/p' <<< "$rec" | tr -d ' ')
  k=$(sed -nE 's/.*(^|;)[[:space:]]*k=([^;]*).*/\2/p' <<< "$rec" | tr -d ' ')
  dk_t=$(sed -nE 's/.*(^|;)[[:space:]]*t=([^;]*).*/\2/p' <<< "$rec" | tr -d ' ')
  k=${k:-rsa}
  info="$k"
  if [ -z "$p" ]; then
    info="revoked (empty p=)"
    add WARN "DKIM selector '$s' is revoked (empty p=). Fine if no system still signs with it."
  elif [ "${k,,}" = rsa ]; then
    bits=""
    if command -v openssl >/dev/null 2>&1; then
      bits=$(printf -- '-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n' "$(fold -w 64 <<< "$p")" |
        openssl pkey -pubin -noout -text 2>/dev/null | sed -nE 's/.*\(([0-9]+) bit\).*/\1/p' | head -1)
    fi
    if [ -z "$bits" ]; then
      info="rsa, key does not parse"
      add FAIL "DKIM selector '$s': the public key does not parse (truncated or broken TXT record?)."
    else
      info="rsa $bits-bit"
      if (( bits < 1024 )); then add FAIL "DKIM selector '$s' uses a $bits-bit key; receivers ignore keys under 1024 bits. Rotate to 2048."
      elif (( bits < 2048 )); then add WARN "DKIM selector '$s' uses a $bits-bit key; 2048 is the recommended minimum."
      fi
    fi
  fi
  [[ $dk_t == *y* ]] && { info+=", test mode (t=y)"; add INFO "DKIM selector '$s' is in test mode (t=y); some receivers treat its results as advisory."; }
  echo "- \`$s\`: $info"
done
if (( found == 0 && probe )); then
  echo "No key found at ${#sels[@]} common selectors."
  add WARN "No DKIM key found at common selectors. Get the real selector from the s= tag of a DKIM-Signature header (parse-headers.sh) and re-run with -s SELECTOR."
fi

# ---------------------------------------------------------------- DMARC
echo
echo "## DMARC"
echo
dmarc_src=$domain
dmarc=$(mdd_dns TXT "_dmarc.$domain" | grep -iE '^v=DMARC1' || true)
org=$(mdd_org_domain "$domain")
if [ -z "$dmarc" ] && [ "$org" != "$domain" ]; then
  dmarc=$(mdd_dns TXT "_dmarc.$org" | grep -iE '^v=DMARC1' || true)
  [ -n "$dmarc" ] && dmarc_src=$org
fi
dmarc_p=""
if [ -z "$dmarc" ]; then
  echo "No DMARC record."
  add FAIL "No DMARC record. Gmail, Yahoo and Microsoft require at least \"v=DMARC1; p=none; rua=mailto:...\" for bulk senders, and it is the only way to see who sends as $domain."
elif (( $(grep -c . <<< "$dmarc") > 1 )); then
  while IFS= read -r l; do printf '%s%s%s\n' '`' "$l" '`'; done <<< "$dmarc"
  add FAIL "_dmarc.$dmarc_src has more than one DMARC record: receivers ignore all of them."
else
  echo "\`$dmarc\`"
  [ "$dmarc_src" != "$domain" ] && echo && echo "(inherited from the organizational domain $dmarc_src)"
  tag() { sed -nE "s/.*(^|;)[[:space:]]*$1[[:space:]]*=[[:space:]]*([^;]*).*/\\2/p" <<< "$dmarc" | sed 's/[[:space:]]*$//' | head -1; }
  dmarc_p=$(tag p); sp=$(tag sp); pct=$(tag pct); rua=$(tag rua); adkim=$(tag adkim); aspf=$(tag aspf)
  [ "$dmarc_src" != "$domain" ] && [ -n "$sp" ] && dmarc_p=$sp
  echo
  echo "| Tag | Value |"
  echo "|---|---|"
  echo "| policy (p / sp) | ${dmarc_p:-missing} / ${sp:-same} |"
  echo "| pct | ${pct:-100} |"
  echo "| alignment (adkim / aspf) | ${adkim:-r} / ${aspf:-r} |"
  echo "| aggregate reports (rua) | ${rua:-none} |"
  case ${dmarc_p,,} in
    reject|quarantine) ;;
    none) add INFO "DMARC p=none: monitoring only, spoofed mail is still delivered. Move to quarantine, then reject, once the reports show all real mail passes." ;;
    *) add FAIL "DMARC record has no valid p= tag; receivers ignore it." ;;
  esac
  [ -n "$pct" ] && [ "$pct" != 100 ] && add INFO "DMARC pct=$pct: the policy applies to only $pct% of failing mail."
  if [ -z "$rua" ]; then
    add WARN "DMARC has no rua= address: you get no aggregate reports and cannot see which senders fail."
  else
    IFS=, read -r -a ruas <<< "$rua"
    for u in "${ruas[@]}"; do
      u=${u//[[:space:]]/}; addr=${u#mailto:}; addr=${addr%%!*}
      rdom=${addr##*@}; rdom=${rdom,,}
      [[ ${u,,} == mailto:* ]] || { add WARN "DMARC rua '$u' is not a mailto: URI."; continue; }
      if [ "$(mdd_org_domain "$rdom")" != "$(mdd_org_domain "$dmarc_src")" ]; then
        auth=$(mdd_dns TXT "$dmarc_src._report._dmarc.$rdom" | grep -iE '^v=DMARC1' || true)
        [ -z "$auth" ] && add WARN "DMARC reports go to $rdom, which has not published $dmarc_src._report._dmarc.$rdom (v=DMARC1); receivers may not send those reports."
      fi
    done
  fi
fi

# ---------------------------------------------------------------- MTA-STS / TLS-RPT / BIMI
echo
echo "## Transport security and branding"
echo
sts=$(mdd_dns TXT "_mta-sts.$domain" | grep -iE '^v=STSv1' || true)
tlsrpt=$(mdd_dns TXT "_smtp._tls.$domain" | grep -iE '^v=TLSRPTv1' || true)
bimi=$(mdd_dns TXT "default._bimi.$domain" | grep -iE '^v=BIMI1' || true)
echo "- MTA-STS: ${sts:-not published}"
if [ -n "$sts" ] && [ -z "${MDD_DNS_FIXTURE:-}" ] && command -v curl >/dev/null 2>&1; then
  pol=$(curl -fsS -m 10 "https://mta-sts.$domain/.well-known/mta-sts.txt" 2>/dev/null | tr -d '\r') || pol=""
  if [ -z "$pol" ]; then
    add FAIL "MTA-STS is announced but https://mta-sts.$domain/.well-known/mta-sts.txt cannot be fetched (DNS, certificate or 404). Senders that enforce it may stop delivering."
  else
    mode=$(sed -n 's/^mode:[[:space:]]*//p' <<< "$pol")
    echo "  - policy mode: ${mode:-missing}"
    while read -r h; do
      [ -z "$h" ] && continue
      ok=0
      while read -r pat; do
        [ -z "$pat" ] && continue
        if [[ $pat == \*.* ]]; then [[ $h == *."${pat#\*.}" && ${h%."${pat#\*.}"} != *.* ]] && ok=1
        else [ "${h,,}" = "${pat,,}" ] && ok=1; fi
      done < <(sed -n 's/^mx:[[:space:]]*//p' <<< "$pol")
      (( ok )) || add FAIL "MX $h is not listed in the MTA-STS policy: senders enforcing MTA-STS will refuse to deliver to it."
    done < <(printf '%s\n' "${mxhosts[@]}")
  fi
fi
echo "- TLS-RPT: ${tlsrpt:-not published}"
echo "- BIMI: ${bimi:-not published}"
[ -z "$tlsrpt" ] && [ -n "$sts" ] && add INFO "MTA-STS without TLS-RPT: you will not hear about TLS delivery failures. Add _smtp._tls.$domain TXT \"v=TLSRPTv1; rua=mailto:...\"."
if [ -n "$bimi" ] && [[ ! ${dmarc_p,,} =~ ^(quarantine|reject)$ ]]; then
  add WARN "BIMI is published but DMARC is not at quarantine/reject: logos are not shown."
fi

if (( test_mx )) && [ ${#mxhosts[@]} -gt 0 ]; then
  echo
  echo "## MX STARTTLS test"
  for h in "${mxhosts[@]}"; do echo; bash "$here/check-smtp.sh" "$h" | sed 's/^# /### /'; done
fi

# ---------------------------------------------------------------- summary
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
(( n == 0 )) && echo "- **OK** No problems found in DNS. If mail still lands in spam or bounces, check the sending IP (check-ip.sh), the server logs (check-server.sh) and a received message's headers (parse-headers.sh)."
exit 0
