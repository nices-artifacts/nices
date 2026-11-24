import json, sys
run = json.load(open(sys.argv[1])); labels = open(sys.argv[2]).read().splitlines()
txs, rcs = run["transactions"], {r["transactionHash"]: r for r in run["receipts"]}
assert len(txs) == len(labels), (len(txs), len(labels))
print("label,gas_used,calldata_bytes,calldata_gas,execution_gas,status")
for t, l in zip(txs, labels):
    r = rcs[t["hash"]]; data = bytes.fromhex(t["transaction"]["input"][2:])
    cd = sum(4 if b == 0 else 16 for b in data); g = int(r["gasUsed"], 16)
    ex = g - 21000 - cd if not l.startswith("deploy") else ""
    print(f"{l},{g},{len(data)},{cd},{ex},{r['status']}")
