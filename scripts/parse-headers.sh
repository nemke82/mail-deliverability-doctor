#!/usr/bin/env bash
# Explain the authentication result of one received message from its raw
# headers: SPF, DKIM and DMARC as the receiver saw them, domain alignment,
# bulk-sender headers, spam scores and the Received path. Local parts of
# addresses are masked in the output.
#
# Usage: parse-headers.sh FILE      (or '-' / no argument to read stdin)
#   Get raw headers from: Gmail "Show original", Outlook "View message source",
#   Thunderbird "View source", or the .eml file.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$here/lib.sh"

case ${1:-} in -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;; esac
src=${1:--}
[ "$src" = - ] || [ -r "$src" ] || mdd_die "cannot read $src"

# Unfold headers (stop at the first empty line), one "name<TAB>value" per header.
hdrs=$(cat -- "$src" | tr -d '\r' | awk '
  /^$/ { if (started) exit; next }
  /^[ \t]/ { if (cur != "") { sub(/^[ \t]+/, " "); val = val $0 }; next }
  /^[A-Za-z0-9-]+:/ { if (cur != "") print cur "\t" val; started = 1
                      i = index($0, ":"); cur = tolower(substr($0, 1, i - 1)); val = substr($0, i + 1); sub(/^[ \t]+/, "", val); next }
  END { if (cur != "") print cur "\t" val }')
[ -n "$hdrs" ] || mdd_die "no headers found"

h1()   { awk -F'\t' -v n="$1" '$1==n { sub(/^[^\t]*\t/, ""); print; exit }' <<< "$hdrs"; }
hall() { awk -F'\t' -v n="$1" '$1==n { sub(/^[^\t]*\t/, ""); print }' <<< "$hdrs"; }
dom_of() { sed -nE 's/.*@([A-Za-z0-9.-]+\.[A-Za-z]{2,}).*/\1/p' <<< "$1" | head -1 | tr '[:upper:]' '[:lower:]'; }
tagv() { sed -nE "s/.*(^|[;[:space:]])$1=([^;[:space:]]+).*/\\2/p" <<< "$2" | head -1; }

from=$(h1 from); rp=$(h1 return-path); subj=$(h1 subject)
from_dom=$(dom_of "$from"); rp_dom=$(dom_of "$rp")
ar=$(h1 authentication-results)
rspf=$(h1 received-spf)

sev=(); msg=()
add() { sev+=("$1"); msg+=("$2"); }

echo "# Message authentication"
echo
echo "| Field | Value |"
echo "|---|---|"
echo "| From domain | ${from_dom:-?} |"
echo "| Envelope sender (Return-Path) domain | ${rp_dom:-? (empty: a bounce/DSN)} |"
echo "| Subject | $(cut -c1-80 <<< "${subj:-}" | mdd_mask_addrs | tr '|' '/') |"
echo "| Date | $(h1 date) |"
echo "| Message-ID domain | $(dom_of "$(h1 message-id)") |"

# ------------------------------------------------ Authentication-Results
spf_r=$(tagv spf "$ar"); dmarc_r=$(tagv dmarc "$ar")
mailfrom=$(tagv smtp.mailfrom "$ar"); mailfrom=${mailfrom##*@}
[ -z "$spf_r" ] && [ -n "$rspf" ] && spf_r=$(awk '{print tolower($1)}' <<< "$rspf")
[ -z "$mailfrom" ] && mailfrom=$rp_dom
compauth=$(tagv compauth "$ar")
dk_pass_doms=""

echo
echo "## Receiver verdict (top Authentication-Results)"
echo
if [ -z "$ar" ] && [ -z "$rspf" ]; then
  echo "No Authentication-Results or Received-SPF header. Use the headers as received"
  echo "by the recipient's mailbox (not the sent copy)."
else
  echo "\`$(cut -c1-600 <<< "$ar" | mdd_mask_addrs)\`"
  echo
  echo "| Check | Result | Domain |"
  echo "|---|---|---|"
  echo "| SPF | ${spf_r:-none} | ${mailfrom:-?} |"
  # each dkim=... result with its header.d / header.i
  while IFS= read -r part; do
    r=$(sed -nE 's/^[[:space:]]*dkim=([a-z]+).*/\1/p' <<< "$part")
    [ -z "$r" ] && continue
    d=$(tagv header.d "$part"); [ -z "$d" ] && { d=$(tagv header.i "$part"); d=${d##*@}; }
    echo "| DKIM | $r | ${d:-?} |"
    [ "$r" = pass ] && dk_pass_doms+=" ${d,,}"
  done < <(tr ';' '\n' <<< "$ar")
  echo "| DMARC | ${dmarc_r:-none} | ${from_dom:-?} |"
  [ -n "$compauth" ] && echo "| Microsoft compauth | $compauth | |"
fi

# ------------------------------------------------ DKIM signatures present
echo
echo "## DKIM signatures in the message"
echo
sigs=$(hall dkim-signature)
if [ -z "$sigs" ]; then
  echo "None."
  add FAIL "The message is not DKIM-signed. Without DKIM, forwarding breaks authentication and DMARC rests on SPF alone. Enable DKIM signing for ${from_dom:-the From domain}."
else
  echo "| d= | s= | a= |"
  echo "|---|---|---|"
  while IFS= read -r s; do
    echo "| $(tagv d "$s") | $(tagv s "$s") | $(tagv a "$s") |"
  done <<< "$sigs"
  echo
  echo "Check a selector's key: \`bash scripts/check-domain.sh -s <s=> <d=>\`"
fi

# ------------------------------------------------ alignment and diagnosis
if [ -n "$from_dom" ]; then
  forg=$(mdd_org_domain "$from_dom")
  spf_aligned=0; dkim_aligned=0
  [ -n "$mailfrom" ] && [ "$(mdd_org_domain "$mailfrom")" = "$forg" ] && spf_aligned=1
  for d in ${dk_pass_doms:-}; do [ "$(mdd_org_domain "$d")" = "$forg" ] && dkim_aligned=1; done
  echo
  echo "## Alignment (relaxed)"
  echo
  echo "- SPF: ${spf_r:-none}, domain ${mailfrom:-?} → $([ $spf_aligned = 1 ] && echo aligned || echo 'not aligned') with $from_dom"
  echo "- DKIM: passing domains:${dk_pass_doms:- none} → $([ $dkim_aligned = 1 ] && echo aligned || echo 'not aligned') with $from_dom"

  spf_ok=0; [ "${spf_r:-}" = pass ] && (( spf_aligned )) && spf_ok=1
  if (( ! spf_ok && ! dkim_aligned )); then
    add FAIL "Neither SPF nor DKIM passes aligned with $from_dom, so DMARC fails. Fix one of them: sign with d=$from_dom (custom DKIM at your ESP), or send with an envelope sender under $from_dom that SPF authorizes."
  elif (( ! dkim_aligned )); then
    add WARN "DMARC passes on SPF only. Forwarded mail and mailing lists break SPF; add DKIM signing with d=$from_dom."
  fi
  if [ "${spf_r:-}" = pass ] && (( ! spf_aligned )); then
    add INFO "SPF passes for $mailfrom, which is not $from_dom (typical for ESPs using their own bounce domain). It does not count for DMARC; a custom return-path/bounce domain under $from_dom fixes that."
  fi
  case ${spf_r:-} in
    fail|softfail) add WARN "SPF $spf_r for $mailfrom: the sending IP is not in that domain's SPF record. Add it (check-domain.sh -i IP $mailfrom)." ;;
    permerror) add FAIL "SPF permerror for $mailfrom: the record is broken (too many lookups, two records, syntax). Run check-domain.sh $mailfrom." ;;
    temperror) add INFO "SPF temperror: the receiver could not query DNS for $mailfrom at that moment." ;;
  esac
  [ -n "$ar" ] && [ -z "$dk_pass_doms" ] && [ -n "$sigs" ] && grep -qE '(^|[;[:space:]])dkim=(fail|neutral|permerror)' <<< "$ar" && add FAIL "DKIM signatures are present but none verified: the body was modified in transit (footer, link rewriting, line-length change) or the DNS key does not match the private key."
fi
case ${dmarc_r:-} in
  fail) add FAIL "The receiver recorded DMARC fail for $from_dom." ;;
esac

# ------------------------------------------------ bulk sender requirements and scores
echo
echo "## Bulk-sender headers and spam scores"
echo
lu=$(h1 list-unsubscribe); lup=$(h1 list-unsubscribe-post)
echo "- List-Unsubscribe: $([ -n "$lu" ] && echo present || echo absent)"
echo "- List-Unsubscribe-Post (one-click): $([ -n "$lup" ] && echo present || echo absent)"
if [ -n "$lu" ] && [ -z "$lup" ]; then
  add WARN "List-Unsubscribe without List-Unsubscribe-Post: One-Click. Gmail and Yahoo require one-click unsubscribe for marketing mail from bulk senders."
fi
scl=$(h1 x-ms-exchange-organization-scl)
[ -z "$scl" ] && scl=$(sed -nE 's/.*SCL:(-?[0-9]+).*/\1/p' <<< "$(h1 x-forefront-antispam-report)")
[ -n "$scl" ] && { echo "- Microsoft SCL: $scl (5+ = junk)"; (( scl >= 5 )) && add WARN "Microsoft scored the message SCL $scl (junk folder)."; }
ss=$(h1 x-spam-status); [ -n "$ss" ] && echo "- X-Spam-Status: $(cut -c1-200 <<< "$ss")"
sc=$(h1 x-spam-score); [ -n "$sc" ] && echo "- X-Spam-Score: $sc"
[ -n "$(h1 x-ms-exchange-organization-authas)" ] && echo "- Microsoft AuthAs: $(h1 x-ms-exchange-organization-authas)"

# ------------------------------------------------ path
echo
echo "## Received path (newest first)"
echo
hall received | head -8 | while IFS= read -r r; do
  fromh=$(sed -nE 's/^from ([^ ]+).*/\1/p' <<< "$r")
  ip=$(grep -oE '\[[0-9a-fA-F:.]+\]' <<< "$r" | head -1 | tr -d '[]')
  by=$(sed -nE 's/.* by ([^ ;]+).*/\1/p' <<< "$r")
  tls=$(grep -oE '(TLS1_[0-9]|TLSv1\.[0-9]|version=TLS[0-9_.]+|ESMTPS|ESMTPSA)' <<< "$r" | head -1)
  echo "- ${fromh:-?} [${ip:-?}] → ${by:-?}${tls:+ ($tls)}"
done
echo
echo "The first hop outside your own systems shows the IP the receiver judged;"
echo "check it with \`bash scripts/check-ip.sh IP\`."

echo
echo "## Findings"
echo
n=0
for want in FAIL WARN INFO; do
  for i in "${!sev[@]}"; do
    [ "${sev[i]}" = "$want" ] || continue
    echo "- **$want** ${msg[i]}"; n=$((n + 1))
  done
done
(( n == 0 )) && echo "- **OK** SPF/DKIM/DMARC pass and align. If the message still went to spam, the cause is reputation or content, not authentication."
exit 0
