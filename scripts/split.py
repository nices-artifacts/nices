"""Splits the execution gas of every contract call into proof verification and the rest.

Usage: split.py <gas.csv> <trace.txt>.  The trace is the -vvvv output of the scenario script; the top-level calls of its first part, the run of the script, to NICES are the non-deployment transactions of gas.csv, in order.  Prints label, transaction gas, calldata gas, verification gas, and the rest of the execution (storage, queue, memo hash, fee), all in gas."""
import csv, re, sys

rows = [r for r in csv.DictReader(open(sys.argv[1])) if not r["label"].startswith("deploy")]
top = re.compile(r"^    ├─ \[\d+\] NICES::\w+")
ver = re.compile(r"\[(\d+)\] Verifier\w+::verify")
calls = []
for line in open(sys.argv[2]):
    if line.startswith("Script ran successfully"):
        break
    if top.match(line):
        calls.append(0)
    elif calls:
        m = ver.search(line)
        if m:
            calls[-1] += int(m.group(1))
assert len(calls) == len(rows), (len(calls), len(rows))
print("label,tx_gas,calldata_gas,verify_gas,rest_gas")
for r, v in zip(rows, calls):
    print(f"{r['label']},{r['gas_used']},{r['calldata_gas']},{v},{int(r['execution_gas']) - v}")
