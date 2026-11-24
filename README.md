# NICES: artifact

This artifact contains the implementation of NICES, non-interactive confidential expense splitting, and the scripts that reproduce every measurement in the evaluation of the paper.  It has three parts: (i) `nices/`, the client, the circuits and the native model in Rust with arkworks, and the contract in Solidity; (ii) `planning/`, the settlement planner in C; and (iii) `scripts/`, one script per result, which write their output to `results/`.

## Requirements

- Linux on x86-64, with `taskset` (util-linux), `curl`, `python3` and `gcc`.
- Rust 1.80 or later (we used 1.99.1), with `cargo`.
- Foundry 1.9.0 (`forge` and `anvil`), installed with `curl -L https://foundry.paradigm.xyz | bash && foundryup --install 1.9.0`.  The scripts look for it in `~/.foundry/bin`.
- 4 GiB of memory, and 3 GiB of disc for the build and the proving keys.

`nices/Cargo.lock` fixes the versions of the Rust crates, and `nices/contracts/lib/forge-std` is the copy of forge-std that the contract scripts use, so the build needs the network only to download the crates.

We measured on one performance core of an Intel Core i7-1260P (16 threads), Fedora 44, power profile `performance`.

## Overview

| Script | Result in the paper | Time |
|---|---|---|
| `scripts/test.sh` | the tests of Section "Evaluation", implementation details | 2 min |
| `scripts/gas.sh` | the table "Cost of a repayment" (gas rows), the gas of the other transactions, and the gas of a post in Section "Off-Chain Groups" | 3 min |
| `scripts/circuits.sh 1 <core>` | the table "Cost of a repayment" (constraints, proving time, memory, proving key), the other relations, and the post relation | 40 min |
| `scripts/circuits.sh 16` | the proving times with all 16 threads | 10 min |
| `scripts/planning.sh <core>` | the table "Greedy versus optimal settlement plans" and the times of the exact program on random balances | 2 min |
| `scripts/settlement.sh quick` | the table "Settlement of a full group on 12 s blocks", tiers 8 and 16, seed 11 | 11 min |
| `scripts/settlement.sh` | the same table, all tiers and seeds | 6 h |

Run them from the root of the artifact, in this order: `scripts/settlement.sh` needs the proving keys that `scripts/gas.sh` writes to `nices/contracts/keys/`.

### The running times above are those of the benchmarks, not of the protocol

The long scripts repeat short operations many times, or wait for blocks in real time.  The time of one operation of the protocol is the following.

| Operation | Time |
|---|---|
| Proving an update (expense or repayment), one thread | 1.9 s for N = 8, 3.4 s for N = 64 |
| Proving an update, all 16 threads | 0.4 s for N = 8, 1.0 s for N = 64 |
| Proving a post of an off-chain group, one thread | 2.6 s for N = 8, 17.8 s for N = 64 |
| Verifying a proof off-chain | 3 to 10 ms |
| Planning a settlement of 20 non-zero balances exactly | 7 ms |
| Settling a full group of 64 members on Ethereum, debtors taking turns | 64 blocks of 12 s, about 13 minutes |

1. `scripts/circuits.sh` takes 40 minutes because it measures 14 relations and tiers, each with a fresh setup and three runs of ten proofs, so that the paper reports medians: 420 proofs in all.
2. `scripts/settlement.sh` takes 6 hours because the chain mines one block every 12 s, as Ethereum does, and the script waits for every block in real time.  It settles 20 groups (tiers 8, 16 and 32 with three seeds each, tier 64 with one seed, each in turn and by racing), and the racing runs of tier 64 take 307 blocks, about one hour, by design: they measure the cost of debtors who do not wait for their turn.  `scripts/settlement.sh quick` runs four of these groups in 11 minutes.

## 1. Tests

`scripts/test.sh` runs the Rust tests and the Foundry test.  The Rust tests run the protocol against the ideal bookkeeping, and check that the circuits reject a repayment above the debt or to a debtor, shares that do not sum to the amount, a share for a padding slot, an expense in the settlement period, a close with non-zero balances, a batch insertion with a wrong root, a post with a forged signature or for fewer members, and a post whose balances do not sum to zero.  Expected: every test passes.

## 2. Gas

`scripts/gas.sh` generates the Groth16 verifiers and a scenario of 101 transactions with real proofs, replays the scenario on a fresh Anvil node, and writes `results/gas.csv`, one row per transaction, and `results/split.csv`, which splits the execution of each call into proof verification and the rest.  The keys come from a local setup with a fixed seed, so every run produces the same proofs.  Expected, in gas, up to a few dozen gas from the zero bytes of the calldata:

| Transaction (`label` in `split.csv`) | N = 8 | N = 16 | N = 32 | N = 64 |
|---|---|---|---|---|
| `update N=… repayment`, `tx_gas` | 474,390 | 536,495 | 660,780 | 909,446 |
| the same, `verify_gas` | 355,972 | 409,276 | 515,884 | 729,100 |
| the same, `rest_gas` | 80,938 | 85,703 | 95,236 | 114,314 |
| the same, calldata bytes (`gas.csv`) | 1,156 | 1,412 | 1,924 | 2,948 |
| `post N=… state` / `post N=… final` | 387,937 / 370,595 | 448,533 / 431,179 | 569,739 / 552,361 | 812,032 / 794,786 |

Moreover: `insertBatch 64 leaves` 770,338, `initGroup` 96,627, `initGroup … off-chain` 141,681, `withdraw` 300,277, `close N=8` 237,895, and a `deposit` 59,967 after the first.  The paper rounds these to thousands; the cost of an update in USD in the paper uses 0.106 gwei and 2,313 USD per ether.

## 3. Circuits

`scripts/circuits.sh 1 <core>` measures every relation with one thread pinned to `<core>`, three runs of ten proofs each, and writes the medians to `results/circuits-1-median.csv`.  Constraints are exact; times and memory depend on the machine.  Expected on our machine:

| Relation, tier | Constraints | Median proving (s) | Peak memory (MiB) | Proving key (MiB) |
|---|---|---|---|---|
| `update`, 8 / 16 / 32 / 64 | 19,588 / 24,364 / 33,428 / 51,068 | 1.9 / 1.9 / 3.0 / 3.4 | 152 / 182 / 259 / 371 | 4.0 / 4.7 / 7.1 / 9.8 |
| `post`, 8 / 64 | 57,753 / 451,657 | 2.6 / 17.8 | 284 / 2,185 | 10.6 / 83.4 |
| `withdraw` | 8,979 | 0.8 | | |
| `insert` | 27,733 | 2.3 | | |
| `close`, 8 … 64 | 2,671 … 16,335 | | | |

`scripts/circuits.sh 16` uses all 16 threads.  Expected: `update` proves in 0.4 s for N = 8 and 1.0 s for N = 64.  Tiers 8 and 16, and tiers 32 and 64, share a size of the FFT domain, hence their similar times.

## 4. Settlement planning

`scripts/planning.sh <core>` compiles `planning/settle.c` and runs it three times.  Each output has two parts.  First, one row per workload (`mode` 0 heterogeneous, 1 recurring) and group size, with the mean number of non-zero balances, the mean number of transfers of greedy and of the optimum, the fraction of instances where greedy is optimal, the worst ratio, and the mean time of the exact program in ms.  The counts are exact and equal the table "Greedy versus optimal settlement plans".  Second, the time of the exact program on random balances: on our machine 7 ms for m = 20, 167 ms for m = 24 and 0.73 s for m = 26.

## 5. Settlement on 12 s blocks

`scripts/settlement.sh` starts a fresh Anvil node per configuration, mining a block every 12 s during settlement, and writes one row per configuration to `results/settlement.csv`: tier, members, strategy (`turns` or `race`), transfers, blocks, seconds, proofs, reverted transactions and gas.  Expected: the transfers equal the table "Settlement of a full group on 12 s blocks"; in turn, settlement takes one block per transfer plus one or two.  Racing depends on how fast the machine proves, so its blocks, proofs and reverted transactions vary with the machine and the run; on any machine it is not faster than taking turns.

## Layout

```
nices/src/            the relations (update.rs, close.rs, withdraw.rs, insert.rs, post.rs), the gadgets, the native model (native.rs, offchain.rs)
nices/src/bin/        bench (circuits), export (verifiers and scenario), settle (settlement on Anvil)
nices/tests/          the protocol tests
nices/contracts/      the Foundry project: src/NICES.sol, the generated Poseidon and verifiers, the generated scripts
nices/run_settle.sh   one Anvil node, deployment and settlement run per configuration
planning/settle.c     greedy and the exact dynamic program
scripts/              the scripts above, and gas.py, split.py and median.py, which read their output
```

## License

The artifact is licensed under the GNU General Public License, version 3 or later (`LICENSE`).  `nices/contracts/lib/forge-std` keeps its own license.
