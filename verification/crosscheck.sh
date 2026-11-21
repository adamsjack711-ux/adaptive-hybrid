#!/bin/sh
set -eu
cd "$(dirname "$0")"
command -v proverif >/dev/null || { echo "Install ProVerif 2.05 (opam install proverif)." >&2; exit 2; }
log=$(mktemp)
trap 'rm -f "$log"' EXIT
for model in Combiner RepeatedBoundaries; do
  proverif "$model.pv" >"$log" || { cat "$log" >&2; exit 1; }
  echo "$model:"
  unique=0
  [ "$model" = RepeatedBoundaries ] && unique=1
  awk -v expected_unique="$unique" '
 /^RESULT / {
   print
   if ($0 ~ / is true\.$/ && $0 ~ /attacker/) secrecy++
   else if ($0 ~ / is true\.$/ && $0 ~ /inj-event/) agreement++
   else if ($0 ~ / is true\.$/ && $0 ~ /&& event\(clientKey/) distinct++
   else if ($0 ~ /^RESULT not event\(serverKey/ && $0 ~ / is false\.$/) reachable++
   else bad++
 }
 END {exit(bad || secrecy != 2 || agreement != 1 || distinct != expected_unique || reachable != 4)}
' "$log"
done
