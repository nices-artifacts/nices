# nices

The NICES protocol with Poseidon encryption of the balances, without ElGamal: the update, close and post relations of each tier, the withdrawal relation and the batch insertion relation of the paper as arkworks circuits for Groth16 over BN254, and a native model of a group and of the note pool that produces their statements and witnesses.

## Layout

```
src/params.rs     Poseidon instance, bounds, tiers, domain tags
src/hash.rs       H_tag, the keystream, Enc and Dec
src/tree.rs       Merkle trees with H_node
src/gadgets.rs    the same in the circuit, range checks, Merkle openings
src/update.rs     R_upd^N, constraints (R1)-(R6) of Figure 1
src/withdraw.rs   R_wd
src/close.rs      R_cl^N
src/insert.rs     R_ins
src/post.rs       R_post^N of an off-chain group, constraints (P1)-(P3)
src/offchain.rs   off-chain groups: EdDSA over Baby Jubjub, co-signed states, posts
src/native.rs     the group, the pool and the contract's state changes
src/bin/bench.rs  constraints, setup, proving and verification time
tests/protocol.rs runs of the protocol and rejected updates
tests/offchain.rs posts, the on-chain continuation, and rejected posts
```

## Use

`cargo test --release` runs the protocol tests.  `cargo run --release --bin bench -- <update|withdraw|close|insert|post> <tier> <runs>` prints one CSV row: relation, tier, public inputs, constraints, setup in s, mean proving time in s, mean verification time in ms, proving key bytes, peak resident memory in MiB.

The public inputs of an update are, in order, gid, t, sigma, kc, the stored root, the old digest, the new digest, the N + 4 entries of the new ciphertext, the memo digest, the pool root, the nullifier, the two note commitments, the fee and the relayer: N + 18 field elements.

## Contracts

`contracts/` is a Foundry project.  `src/NICES.sol` is the contract of Algorithm 1, settled in ETH, with the pool tree inserted in pairs.  `cargo run --release --bin export -- contracts` writes from the Rust side the unrolled Poseidon (`src/PoseidonT3.sol`, checked against arkworks), the Groth16 verifiers of every relation (`src/Verifiers.sol`), a Poseidon test (`test/Poseidon.t.sol`) and a script that replays a scenario with real proofs (`script/Scenario.s.sol`, its transactions named in order in `script/labels.txt`).  To measure gas: run `anvil`, then `forge script script/Scenario.s.sol:Scenario --rpc-url http://127.0.0.1:8545 --broadcast --private-key <anvil key 0> --disable-code-size-limit --slow`, and read the receipts in `broadcast/`.
