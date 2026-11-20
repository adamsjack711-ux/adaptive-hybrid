#!/bin/sh
set -eu
cd "$(dirname "$0")"
case "${1:-}" in
    "") set -- Advisory Boundary ForkReachability ;;
    --fast) set -- Advisory Boundary ;;
    --slow) set -- ForkReachability ;;
    --exploratory) set -- ForkWitness ;;
    *) echo "Usage: $0 [--fast|--slow|--exploratory]" >&2; exit 2 ;;
esac
for cmd in tamarin-prover maude python3; do
    command -v "$cmd" >/dev/null || { echo "Install $cmd and add it to PATH." >&2; exit 2; }
done
log=$(mktemp)
trap 'rm -f "$log"' EXIT
run_bounded() {
    python3 -c '
import subprocess
import sys

try:
    sys.exit(subprocess.call(sys.argv[2:], timeout=int(sys.argv[1])))
except subprocess.TimeoutExpired:
    sys.exit(f"Tamarin search exceeded {sys.argv[1]} seconds")
' "$@"
}
for theory do
    expected=$(grep -c '^lemma ' "$theory.spthy")
    selected=""
    case "$theory" in
        ForkReachability)
            set -- 900 tamarin-prover --derivcheck-timeout=30 --prove --heuristic=O --oraclename=oracle.py "$theory.spthy" +RTS -N4 -M8g -RTS ;;
        ForkWitness)
            selected=two_certificate_fork_witness
            expected=1
            set -- "${EXPLORATORY_TIMEOUT:-900}" tamarin-prover --derivcheck-timeout=30 --prove="$selected" "$theory.spthy" +RTS -N2 -M4g -RTS ;;
        *)
            set -- 120 tamarin-prover --derivcheck-timeout=30 --prove "$theory.spthy" +RTS -N2 -RTS ;;
    esac
    if ! run_bounded "$@" >"$log" 2>&1; then
        tail -n 40 "$log" >&2
        exit 1
    fi
    sed -n '/^summary of summaries:/,$p' "$log"
    # Tamarin also exits zero for an incomplete proof or a counterexample.
    grep -q 'All wellformedness checks were successful' "$log" || { cat "$log" >&2; exit 1; }
    awk -v expected="$expected" -v selected="$selected" '
      /^summary of summaries:/ {summary=1}
      summary && /\((all-traces|exists-trace)\):/ && (selected == "" || $1 == selected) {
        count++
        if ($0 !~ /: verified /) failed=1
      }
      END {exit(failed || count != expected)}
    ' "$log"
done
