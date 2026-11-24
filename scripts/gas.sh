#!/bin/sh
# Gas of every transaction: generates the verifiers and a scenario with real proofs, replays it on a fresh Anvil node, and reads the receipts.
# Output: results/gas.csv (every transaction), results/split.csv (verification and the rest of the execution), results/trace.txt.
set -eu
. "$(dirname "$0")/env.sh"
cd "$nices" && cargo build --release --bin export && ./target/release/export contracts
anvil --port 8545 --gas-limit 100000000 --code-size-limit 100000 --silent &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
until curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' http://127.0.0.1:8545 >/dev/null 2>&1; do sleep 0.2; done
cd "$nices/contracts"
rm -rf broadcast/Scenario.s.sol
forge script script/Scenario.s.sol:Scenario --rpc-url http://127.0.0.1:8545 --broadcast --private-key $key --disable-code-size-limit --slow -vvvv > "$results/trace.txt" 2>&1
python3 "$root/scripts/gas.py" broadcast/Scenario.s.sol/31337/run-latest.json script/labels.txt > "$results/gas.csv"
python3 "$root/scripts/split.py" "$results/gas.csv" "$results/trace.txt" > "$results/split.csv"
if grep -q ',0x0$' "$results/gas.csv"; then echo "a transaction failed" >&2; exit 1; fi
grep -E '^(initGroup|update N=[0-9]+ repayment|post|close|withdraw|deposit|insertBatch 64)' "$results/split.csv" | sort -u -t, -k1,1
