#!/usr/bin/env bash
# Shared helpers for mail-deliverability-doctor. Sourced by the other scripts.
#
# Environment:
#   MDD_RESOLVER      query this DNS server instead of the system resolver (e.g. 1.1.1.1)
#   MDD_DNS_FIXTURE   tab-separated file "name<TAB>TYPE<TAB>value" used instead of DNS (tests)

mdd_die()  { printf 'error: %s\n' "$*" >&2; exit 2; }
mdd_warn() { printf 'warning: %s\n' "$*" >&2; }

mdd_need_dig() {
  [ -n "${MDD_DNS_FIXTURE:-}" ] && return 0
  command -v dig >/dev/null 2>&1 ||
    mdd_die "dig not found: install bind-utils (Fedora/RHEL/Alma) or dnsutils (Debian/Ubuntu)"
}

# mdd_dns TYPE NAME: one answer per line. TXT strings are unquoted and joined.
# Prints nothing when the name has no such record or the query fails.
mdd_dns() {
  local type=${1^^} name=${2,,} out
  name=${name%.}
  if [ -n "${MDD_DNS_FIXTURE:-}" ]; then
    awk -F'\t' -v n="$name" -v t="$type" 'tolower($1)==n && $2==t {print $3}' "$MDD_DNS_FIXTURE"
    return 0
  fi
  out=$(dig +short +time=3 +tries=2 ${MDD_RESOLVER:+"@$MDD_RESOLVER"} "$type" "$name" 2>/dev/null) || true
  if grep -q '^;;' <<< "$out"; then
    mdd_warn "DNS query failed or timed out: $type $name"
    out=$(grep -v '^;;' <<< "$out" || true)
  fi
  [ -n "$out" ] || return 0
  case $type in
    TXT)  grep '^"' <<< "$out" | sed -e 's/^"//' -e 's/"$//' -e 's/" "//g' || true ;;
    A)    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' <<< "$out" || true ;;
    AAAA) grep -E '^[0-9a-fA-F:]*:[0-9a-fA-F:]*$' <<< "$out" || true ;;
    *)    printf '%s\n' "$out" ;;
  esac
}

# Addresses (A and AAAA) of a host name.
mdd_addrs() { mdd_dns A "$1"; mdd_dns AAAA "$1"; }

mdd_is_domain() {
  [[ ${#1} -le 253 && ${1,,} =~ ^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$ ]]
}

mdd_is_ipv4() {
  [[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  local o
  for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
}

mdd_is_ipv6() { [[ $1 == *:* && $1 =~ ^[0-9A-Fa-f:]{2,39}$ ]]; }

mdd_ip2int() {
  local a b c d
  IFS=. read -r a b c d <<< "$1"
  echo $(( (10#$a << 24) + (10#$b << 16) + (10#$c << 8) + 10#$d ))
}

# mdd_in_cidr IP NET[/BITS]: IPv4 only.
mdd_in_cidr() {
  local ip=$1 net=${2%/*} bits=32 mask
  [[ $2 == */* ]] && bits=${2#*/}
  mdd_is_ipv4 "$ip" && mdd_is_ipv4 "$net" || return 1
  [[ $bits =~ ^[0-9]{1,2}$ ]] && (( bits <= 32 )) || return 1
  mask=$(( bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
  (( ($(mdd_ip2int "$ip") & mask) == ($(mdd_ip2int "$net") & mask) ))
}

# Full 32-nibble form of an IPv6 address (no embedded IPv4 support).
mdd_expand6() {
  local ip=${1,,} head tail g out="" i n
  local -a h=() t=() all=()
  if [[ $ip == *::* ]]; then head=${ip%%::*}; tail=${ip#*::}; else head=$ip; tail=""; fi
  [ -n "$head" ] && IFS=: read -r -a h <<< "$head"
  [ -n "$tail" ] && IFS=: read -r -a t <<< "$tail"
  n=$(( 8 - ${#h[@]} - ${#t[@]} ))
  all=("${h[@]}")
  for (( i = 0; i < n; i++ )); do all+=(0); done
  all+=("${t[@]}")
  for g in "${all[@]}"; do out+=$(printf '%04x' "0x${g:-0}"); done
  echo "$out"
}

# Reverse-lookup label for an IP: 4.3.2.1 or nibbles for IPv6 (without the zone).
mdd_rev() {
  if mdd_is_ipv4 "$1"; then
    local a b c d
    IFS=. read -r a b c d <<< "$1"
    echo "$d.$c.$b.$a"
  else
    mdd_expand6 "$1" | rev | sed 's/./&./g; s/\.$//'
  fi
}

mdd_ptr_name() {
  if mdd_is_ipv4 "$1"; then echo "$(mdd_rev "$1").in-addr.arpa"; else echo "$(mdd_rev "$1").ip6.arpa"; fi
}

# Organizational domain, approximated: the last two labels, or three when the
# second-level label is a common registry suffix (co.uk, com.au, org.rs ...).
# Not a full Public Suffix List lookup.
mdd_org_domain() {
  local d=${1,,} n
  local -a l
  d=${d%.}
  IFS=. read -r -a l <<< "$d"
  n=${#l[@]}
  if (( n <= 2 )); then echo "$d"; return; fi
  if [[ ${l[n-2]} =~ ^(co|com|net|org|gov|edu|ac|or|ne|go|in|gen|ltd|plc|nom|biz|info|me|sch|mil)$ && ${#l[n-1]} -eq 2 ]]; then
    echo "${l[n-3]}.${l[n-2]}.${l[n-1]}"
  else
    echo "${l[n-2]}.${l[n-1]}"
  fi
}

# Hide the local part of e-mail addresses in a line of text.
mdd_mask_addrs() { sed -E 's/[A-Za-z0-9._%+=-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})/…@\1/g'; }
