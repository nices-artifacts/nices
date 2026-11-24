#!/bin/sh
# Settlement of a full group on 12 s blocks, in turn and by racing: seeds 11 to 13 for N <= 32 and seed 11 for N = 64.
# Usage: settlement.sh [quick].  "quick" runs N = 8 and 16 with seed 11 only, in about 11 minutes; the full run takes several hours.
# Needs the proving keys of gas.sh (nices/contracts/keys).  Output: results/settlement.csv.
set -eu
. "$(dirname "$0")/env.sh"
test -d "$nices/contracts/keys" || { echo "run scripts/gas.sh first" >&2; exit 1; }
cd "$nices" && cargo build --release --bin settle
out=$results/settlement.csv
echo "tier,members,strategy,transfers,blocks,seconds,proofs,reverted,gas" > "$out"
if [ "${1:-}" = quick ]; then
    cfgs="8:8:turns:11 8:8:race:11 16:16:turns:11 16:16:race:11"
else
    cfgs=""
    for n in 8 16 32; do for s in 11 12 13; do cfgs="$cfgs $n:$n:turns:$s $n:$n:race:$s"; done; done
    cfgs="$cfgs 64:64:turns:11 64:64:race:11"
fi
sh "$nices/run_settle.sh" "$out" $cfgs
cat "$out"
