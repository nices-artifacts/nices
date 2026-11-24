#!/bin/sh
# Settlement planning: greedy against the exact dynamic program on the two workloads, and the time of the exact program on random balances.
# Usage: planning.sh [core].  Output: results/planning-<run>.txt for three runs pinned to the core (default 0).
set -eu
. "$(dirname "$0")/env.sh"
core=${1:-0}
gcc -O2 -o "$results/settle" "$root/planning/settle.c"
for run in 1 2 3; do taskset -c "$core" "$results/settle" > "$results/planning-$run.txt"; done
cat "$results/planning-1.txt"
