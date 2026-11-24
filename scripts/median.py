"""Medians over the runs of bench: one row per relation and tier.

Usage: median.py <circuits.csv>, the rows of `bench`: relation, tier, public inputs, constraints, setup s, mean proving s, mean verification ms, proving key bytes, peak memory MiB."""
import csv, statistics, sys
from collections import defaultdict

runs = defaultdict(list)
for r in csv.reader(open(sys.argv[1])):
    if r and r[0] != "relation":
        runs[(r[0], int(r[1]))].append(r)
print("relation,tier,public_inputs,constraints,median_proving_s,min_proving_s,max_proving_s,verification_ms,proving_key_mib,peak_memory_mib")
for (rel, tier), rs in runs.items():
    p = [float(r[5]) for r in rs]
    print(f"{rel},{tier},{rs[0][2]},{rs[0][3]},{statistics.median(p):.2f},{min(p):.2f},{max(p):.2f},"
          f"{statistics.median(float(r[6]) for r in rs):.1f},{int(rs[0][7]) / 2**20:.1f},{max(float(r[8]) for r in rs):.0f}")
