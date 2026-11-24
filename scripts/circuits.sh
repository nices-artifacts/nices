#!/bin/sh
# Constraints, proving time, verification time, proving key size and memory of every relation and tier: three runs of ten proofs each.
# Usage: circuits.sh [threads] [core].  With one thread (the default) the prover is pinned to the given core (default 0); the paper used a performance core.
# Output: results/circuits-<threads>.csv (every run) and results/circuits-<threads>-median.csv.
set -eu
. "$(dirname "$0")/env.sh"
threads=${1:-1}
core=${2:-0}
cd "$nices" && cargo build --release --bin bench
out=$results/circuits-$threads.csv
echo "relation,tier,public_inputs,constraints,setup_s,mean_proving_s,mean_verification_ms,proving_key_bytes,peak_memory_mib" > "$out"
bench() {
    if [ "$threads" = 1 ]; then RAYON_NUM_THREADS=1 taskset -c "$core" "$nices/target/release/bench" "$@"; else RAYON_NUM_THREADS=$threads "$nices/target/release/bench" "$@"; fi
}
for run in 1 2 3; do
    for n in 8 16 32 64; do
        for rel in update close post; do
            echo "run $run: $rel N=$n" >&2
            bench $rel $n 10 >> "$out"
        done
    done
    for rel in withdraw insert; do
        echo "run $run: $rel" >&2
        bench $rel 8 10 >> "$out"
    done
done
python3 "$root/scripts/median.py" "$out" | tee "$results/circuits-$threads-median.csv"
