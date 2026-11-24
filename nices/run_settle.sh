#!/bin/sh
# The settlement experiment: for each configuration, a fresh Anvil node, a fresh deployment, and one run of target/release/settle.
# Usage: run_settle.sh <out.csv> <tier>:<members>:<strategy>:<seed> ...
# Progress, with the time elapsed and an estimate of the time remaining, goes to the terminal (/dev/tty), or to stderr without one.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
forge=${FORGE:-$HOME/.foundry/bin/forge}
anvil=${ANVIL:-$HOME/.foundry/bin/anvil}
out=$1
shift
key=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
if (: > /dev/tty) 2>/dev/null; then tty=/dev/tty; else tty=/dev/stderr; fi
# The expected duration of a run, in seconds: one 12 s block per member for the settlement, and about 3 s per member for the setup.
weight() { IFS=: read -r _t m _s _r <<W
$1
W
    echo $((15 * m + 10)); }
total=0
for cfg in "$@"; do total=$((total + $(weight "$cfg"))); done
mmss() { printf '%d:%02d' $(($1 / 60)) $(($1 % 60)); }
begin=$(date +%s)
done_w=0
i=0
n=$#
for cfg in "$@"; do
    i=$((i + 1))
    elapsed=$(($(date +%s) - begin))
    if [ $done_w -gt 0 ]; then left=$((elapsed * (total - done_w) / done_w)); else left=$total; fi
    printf '[%d/%d] %s  elapsed %s  remaining about %s\n' $i $n "$cfg" "$(mmss $elapsed)" "$(mmss $left)" > $tty
    IFS=: read -r tier members strategy seed <<CFG
$cfg
CFG
    "$anvil" --port 8545 --accounts 70 --balance 1000000 --silent &
    pid=$!
    until curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' http://127.0.0.1:8545 >/dev/null 2>&1; do sleep 0.2; done
    addr=$(cd "$here/contracts" && "$forge" script script/Deploy.s.sol:Deploy --rpc-url http://127.0.0.1:8545 --broadcast --private-key $key --disable-code-size-limit 2>&1 | sed -n 's/.*NICES \(0x[0-9a-fA-F]*\).*/\1/p' | head -1)
    RAYON_NUM_THREADS=1 "$here/target/release/settle" http://127.0.0.1:8545 "$addr" "$here/contracts/keys" "$tier" "$members" "$strategy" "$seed" >> "$out"
    kill $pid
    wait $pid 2>/dev/null || true
    done_w=$((done_w + $(weight "$cfg")))
done
printf 'finished in %s\n' "$(mmss $(($(date +%s) - begin)))" > $tty
