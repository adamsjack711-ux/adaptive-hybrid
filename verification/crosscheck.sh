#!/bin/sh
set -eu
cd "$(dirname "$0")"
command -v proverif >/dev/null || { echo "Install ProVerif 2.05 (opam install proverif)." >&2; exit 2; }
log=$(mktemp)
trap 'rm -f "$log"' EXIT
proverif Combiner.pv >"$log" || { cat "$log" >&2; exit 1; }
awk '
 /^RESULT / {
   print
   if ($0 ~ / is true\.$/ && $0 ~ /attacker|inj-event/) safety++
   else if ($0 ~ /^RESULT not event\(serverKey/ && $0 ~ / is false\.$/) reachable++
   else bad++
 }
 END {exit(bad || safety != 3 || reachable != 4)}
' "$log"
