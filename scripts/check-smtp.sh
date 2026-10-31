#!/usr/bin/env bash
# Read-only SMTP check of one mail server: connects, reads the banner, sends
# EHLO and QUIT (no mail is sent), then tests STARTTLS and the certificate.
#
# Usage: check-smtp.sh [-p PORT] [-e EHLO_NAME] HOST
#   -p PORT   default 25 (use 587 for submission)
#   -e NAME   name to announce in EHLO (default: this machine's FQDN)
#
# Many clouds and ISPs block outbound port 25; a timeout here often means the
# machine you run it from cannot reach port 25 at all, not that the MX is down.
set -uo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$here/lib.sh"

# Internal: the plain-text conversation, run under timeout in a child bash.
if [ "${1:-}" = __talk ]; then
  host=$2 port=$3 ehlo=$4
  exec 3<>"/dev/tcp/$host/$port" || exit 3
  while IFS= read -r -t 20 line <&3; do
    line=${line%$'\r'}; echo "S: $line"
    [[ $line =~ ^[0-9]{3}- ]] || break
  done
  printf 'EHLO %s\r\n' "$ehlo" >&3
  while IFS= read -r -t 20 line <&3; do
    line=${line%$'\r'}; echo "S: $line"
    [[ $line =~ ^[0-9]{3}- ]] || break
  done
  printf 'QUIT\r\n' >&3
  exec 3>&-
  exit 0
fi

usage() { sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
port=25
ehlo=$(hostname -f 2>/dev/null || hostname)
while getopts 'p:e:h' o; do
  case $o in
    p) if ! [[ $OPTARG =~ ^[0-9]{1,5}$ ]] || (( OPTARG > 65535 )); then mdd_die "bad port: $OPTARG"; fi; port=$OPTARG ;;
    e) mdd_is_domain "$OPTARG" || mdd_die "EHLO name must be a FQDN: $OPTARG"; ehlo=$OPTARG ;;
    h) usage 0 ;;
    *) usage 1 ;;
  esac
done
shift $((OPTIND - 1))
[ $# -eq 1 ] || usage 1
host=${1%.}
mdd_is_domain "$host" || mdd_is_ipv4 "$host" || mdd_die "not a host name: $1"
mdd_is_domain "$ehlo" || ehlo="localhost.localdomain"

sev=(); msg=()
add() { sev+=("$1"); msg+=("$2"); }

echo "# SMTP check: $host:$port"
echo
conv=""
# shellcheck disable=SC2016  # $1/$2 expand in the child shell
if timeout 10 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$host" "$port" 2>/dev/null; then
  conv=$(timeout 45 bash "$0" __talk "$host" "$port" "$ehlo" 2>/dev/null); rc=$?
else
  rc=$?
fi
if [ $rc -ne 0 ] || [ -z "$conv" ]; then
  echo "Could not talk SMTP to $host:$port (exit $rc)."
  add FAIL "No SMTP connection to $host:$port. Either the server is down/firewalled or this machine cannot open outbound port $port (common on cloud VMs and home ISPs): try from another host."
else
  echo '```'
  printf '%s\n' "$conv"
  echo '```'
  banner=$(head -1 <<< "$conv" | sed 's/^S: //')
  [[ $banner == 220* ]] || add FAIL "Banner is not 220: '$banner'. The server refuses connections from here (blocked IP?)."
  bname=$(awk '{print $2}' <<< "${banner#220-}" | tr '[:upper:]' '[:lower:]')
  if [ "$port" = 25 ] && mdd_is_domain "$bname" && ! mdd_is_ipv4 "$host"; then
    for a in $(mdd_dns A "$host"); do
      ptr=$(mdd_dns PTR "$(mdd_ptr_name "$a")" | sed 's/\.$//' | head -1)
      [ -n "$ptr" ] && [ "${ptr,,}" != "$bname" ] && add INFO "Banner name $bname differs from the PTR of $a ($ptr)."
    done
  fi
  grep -qi '^S: 250[- ]STARTTLS' <<< "$conv" || add FAIL "STARTTLS is not offered: mail to this server travels unencrypted, and Gmail marks it with a red lock."
  sz=$(sed -nE 's/^S: 250[- ]SIZE ([0-9]+).*/\1/p' <<< "$conv" | head -1)
  [ -n "$sz" ] && (( sz > 0 && sz < 10485760 )) && add INFO "SIZE limit is $((sz / 1048576)) MB; larger messages bounce."
fi

if [ $rc -eq 0 ] && grep -qi '^S: 250[- ]STARTTLS' <<< "$conv" && command -v openssl >/dev/null 2>&1; then
  echo
  echo "## TLS"
  echo
  sc=( -connect "$host:$port" -crlf )
  [ "$port" != 465 ] && sc+=( -starttls smtp )
  mdd_is_domain "$host" && sc+=( -servername "$host" -verify_hostname "$host" )
  out=$(timeout 30 openssl s_client "${sc[@]}" < /dev/null 2>&1)
  cert=$(sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' <<< "$out")
  proto=$(sed -nE 's/^ *Protocol *: *(.*)/\1/p; s/^New, (TLSv[0-9.]+).*/\1/p' <<< "$out" | head -1)
  verify=$(sed -nE 's/^ *Verify return code: (.*)/\1/p' <<< "$out" | tail -1)
  echo "- Protocol: ${proto:-unknown}"
  echo "- Verification: ${verify:-unknown}"
  if [ -n "$cert" ]; then
    subj=$(openssl x509 -noout -subject <<< "$cert" 2>/dev/null | sed 's/^subject=//')
    san=$(openssl x509 -noout -ext subjectAltName <<< "$cert" 2>/dev/null | tail -n +2 | sed 's/^ *//')
    end=$(openssl x509 -noout -enddate <<< "$cert" 2>/dev/null | cut -d= -f2)
    echo "- Subject: $subj"
    echo "- Names: ${san:-none}"
    echo "- Expires: $end"
    if [ -n "$end" ]; then
      days=$(( ( $(date -d "$end" +%s) - $(date +%s) ) / 86400 ))
      if (( days < 0 )); then add FAIL "TLS certificate expired $(( -days )) days ago."
      elif (( days < 14 )); then add WARN "TLS certificate expires in $days days."
      fi
    fi
  fi
  [[ ${verify:-} == 0* ]] || add WARN "Certificate does not verify for $host (${verify:-no result}). Opportunistic TLS still works, but MTA-STS/DANE senders will refuse it."
  [[ ${proto:-} =~ TLSv1(\.[01])?$ ]] && add WARN "Negotiated $proto; TLS 1.2 or newer is expected."
fi

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
(( n == 0 )) && echo "- **OK** SMTP answers, offers STARTTLS and the certificate verifies."
exit 0
