//! The settlement experiment: the members of one group record expenses, then every debtor repays according to a plan on a chain with fixed block time, and a member closes the group.
//!
//! Usage: settle <rpc url> <NICES address> <keys dir> <tier N> <members n> <race|turns> <seed>.  Prints one CSV row: tier, members, strategy, transfers, blocks, seconds, proofs, reverted, gas.
//!
//! The chain is an Anvil node with unlocked accounts, automining during the setup; the experiment switches it to interval mining of 12 s for the settlement.  In `turns`, the debtors repay one after another in the order of the plan, each after the previous repayment is included.  In `race`, every debtor with a remaining transfer proves it against the current state and submits it at once; the chain accepts one, and the others recompute their proof against the new state and submit again.

use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use nices::close::CloseCircuit;
use nices::hash::h;
use nices::insert::InsertCircuit;
use nices::native::{Group, Note, Op, Pool};
use nices::params::{Tag, MEMO_LEN};
use nices::update::UpdateCircuit;
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tiny_keccak::{Hasher, Keccak};

const HEND: u64 = 1_000_000_000;
const BLOCK_TIME: u64 = 12;
const NOTE_VALUE: u64 = 10_000_000;

struct Rpc {
    url: String,
}

impl Rpc {
    fn call(&self, method: &str, params: Value) -> Value {
        let r: Value = ureq::post(&self.url)
            .send_json(json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .unwrap()
            .into_json()
            .unwrap();
        if let Some(e) = r.get("error") {
            panic!("{method}: {e}");
        }
        r["result"].clone()
    }

    fn send(&self, from: &str, to: &str, data: &[u8], value: u64) -> String {
        let tx = json!([{"from": from, "to": to, "data": hex(data), "value": format!("0x{value:x}"), "gas": "0x2dc6c0"}]);
        self.call("eth_sendTransaction", tx).as_str().unwrap().to_string()
    }

    /// Waits for the receipt and returns (status, gas used, block).
    fn wait(&self, tx: &str) -> (bool, u64, u64) {
        loop {
            let r = self.call("eth_getTransactionReceipt", json!([tx]));
            if !r.is_null() {
                let n = |k: &str| u64::from_str_radix(r[k].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
                return (n("status") == 1, n("gasUsed"), n("blockNumber"));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn block(&self) -> u64 {
        u64::from_str_radix(self.call("eth_blockNumber", json!([])).as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::from("0x");
    for x in b {
        s += &format!("{x:02x}");
    }
    s
}

fn selector(sig: &str) -> Vec<u8> {
    let mut k = Keccak::v256();
    k.update(sig.as_bytes());
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out[..4].to_vec()
}

fn word<F: PrimeField>(x: F) -> Vec<u8> {
    let b = x.into_bigint().to_bytes_be();
    let mut w = vec![0u8; 32 - b.len()];
    w.extend(b);
    w
}

fn wu(x: u64) -> Vec<u8> {
    word(Fr::from(x))
}

fn proof_words(p: &Proof<Bn254>) -> Vec<u8> {
    [word(p.a.x), word(p.a.y), word(p.b.x.c1), word(p.b.x.c0), word(p.b.y.c1), word(p.b.y.c0), word(p.c.x), word(p.c.y)].concat()
}

fn enc_update(c: &UpdateCircuit, z: &[Fr], p: &Proof<Bn254>) -> Vec<u8> {
    let x = &c.x;
    let mut d = selector("update((uint256,uint256,uint256[],uint256,uint256[4],uint256,uint256,uint256,uint256,uint256,uint256,uint256[8]))");
    d.extend(wu(0x20));
    d.extend([word(x.gid), word(x.t), wu(22 * 32), word(x.h_cn)].concat());
    for v in z {
        d.extend(word(*v));
    }
    for v in [x.prt, x.nf, x.cm_out, x.cm_chg, x.fee, x.rel] {
        d.extend(word(v));
    }
    d.extend(proof_words(p));
    d.extend(wu(x.c_new.len() as u64));
    for v in &x.c_new {
        d.extend(word(*v));
    }
    d
}

fn enc_insert(c: &InsertCircuit, p: &Proof<Bn254>) -> Vec<u8> {
    let mut d = selector("insertBatch(uint256[],uint256,uint256[8])");
    d.extend(wu(10 * 32));
    d.extend(word(c.new_root));
    d.extend(proof_words(p));
    d.extend(wu(c.real as u64));
    for v in &c.leaves[..c.real] {
        d.extend(word(*v));
    }
    d
}

fn load(dir: &str, name: &str) -> ProvingKey<Bn254> {
    let f = std::io::BufReader::new(std::fs::File::open(format!("{dir}/{name}.pk")).unwrap());
    ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(f).unwrap()
}

/// The equal split of a among n members, the remainder one unit each to the first members.
fn split(a: u64, n: usize) -> Vec<u64> {
    (0..n).map(|l| a / n as u64 + u64::from((l as u64) < a % n as u64)).collect()
}

/// A bipartite plan by the greedy rule: the largest debtor pays the largest creditor.  Slots are 1-based.
fn plan(mut b: Vec<i128>) -> Vec<(usize, usize, u64)> {
    let mut v = Vec::new();
    loop {
        let (d, dv) = b.iter().enumerate().min_by_key(|(_, x)| **x).map(|(i, x)| (i, *x)).unwrap();
        if dv == 0 {
            return v;
        }
        let (c, cv) = b.iter().enumerate().max_by_key(|(_, x)| **x).map(|(i, x)| (i, *x)).unwrap();
        let a = (-dv).min(cv);
        b[d] += a;
        b[c] -= a;
        v.push((d + 1, c + 1, a as u64));
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let rpc = Rpc { url: a[1].clone() };
    let nices = a[2].clone();
    let keys = a[3].clone();
    let tier: usize = a[4].parse().unwrap();
    let n: usize = a[5].parse().unwrap();
    let strategy = a[6].clone();
    let seed: u64 = a[7].parse().unwrap();
    let mut rng = StdRng::seed_from_u64(seed);
    let accounts: Vec<String> = rpc.call("eth_accounts", json!([])).as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect();
    assert!(accounts.len() > n, "start anvil with more accounts");
    let pk_upd = load(&keys, &format!("update{tier}"));
    let pk_cl = load(&keys, &format!("close{tier}"));
    let pk_ins = load(&keys, "insert");
    let memo = [Fr::from(1u64); MEMO_LEN];
    rpc.call("evm_setAutomine", json!([true]));

    // Expenses: member l pays an amount between 10.00 and 200.00, split equally among all members.
    let amounts: Vec<u64> = (0..n).map(|_| rng.gen_range(1_000..=20_000)).collect();
    let mut b = vec![0i128; n];
    for (l, &am) in amounts.iter().enumerate() {
        b[l] += am as i128;
        for (k, s) in split(am, n).iter().enumerate() {
            b[k] -= *s as i128;
        }
    }
    let transfers = plan(b.clone());

    // Setup: deposits, one note per expense and one per transfer of each member, inserted in batches; the group; the expenses.
    let mut g = Group::form(n, tier, HEND, &mut rng);
    let mut pool = Pool::new();
    let mut notes: Vec<Vec<Note>> = vec![Vec::new(); n];
    let mut last = String::new();
    for l in 0..n {
        let k = 1 + transfers.iter().filter(|t| t.0 == l + 1).count();
        for _ in 0..k {
            let note = pool.deposit(NOTE_VALUE, g.members[l].nsk, &mut rng);
            let u = h(Tag::Own, &[note.addr(), note.rho]);
            let data = [selector("deposit(uint256,uint256)"), wu(NOTE_VALUE), word(u)].concat();
            last = rpc.send(&accounts[0], &nices, &data, NOTE_VALUE);
            notes[l].push(note);
        }
    }
    assert!(rpc.wait(&last).0);
    while pool.pending() {
        let c = pool.insert_batch();
        let p = Groth16::<Bn254>::prove(&pk_ins, c.clone(), &mut rng).unwrap();
        assert!(rpc.wait(&rpc.send(&accounts[0], &nices, &enc_insert(&c, &p), 0)).0, "insertBatch");
    }
    let data = [selector("initGroup(uint256,uint256,uint64,uint64,uint256,uint64)"), word(g.kc), word(g.mroot_s), wu(tier as u64), wu(HEND), wu(0), wu(0)].concat();
    assert!(rpc.wait(&rpc.send(&accounts[0], &nices, &data, 0)).0, "initGroup");
    let rel = Fr::from_be_bytes_mod_order(&{
        let s = accounts[0].trim_start_matches("0x");
        (0..20).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect::<Vec<u8>>()
    });
    for l in 0..n {
        let input = notes[l].remove(0);
        let (c, _, _, z) = g.update(&mut pool, l + 1, Op::Expense { a: amounts[l], s: split(amounts[l], n) }, &input, 1, rel, memo, &mut rng);
        let p = Groth16::<Bn254>::prove(&pk_upd, c.clone(), &mut rng).unwrap();
        assert!(rpc.wait(&rpc.send(&accounts[l + 1], &nices, &enc_update(&c, &z, &p), 0)).0, "expense");
    }
    assert_eq!(g.balances()[..n], b[..]);

    // Settlement on 12 s blocks.
    rpc.call("evm_setAutomine", json!([false]));
    rpc.call("evm_setIntervalMining", json!([BLOCK_TIME]));
    let start_block = rpc.block();
    let start = Instant::now();
    let (mut proofs, mut reverted, mut gas) = (0u64, 0u64, 0u64);
    let mut remaining: Vec<Vec<(usize, u64)>> = vec![Vec::new(); n];
    for &(d, c, am) in &transfers {
        remaining[d - 1].push((c, am));
    }
    let mut order = transfers.clone();
    while remaining.iter().any(|r| !r.is_empty()) {
        // The debtors who prove and submit in this round.
        let movers: Vec<usize> = if strategy == "turns" {
            let (d, _, _) = order.remove(0);
            vec![d - 1]
        } else {
            (0..n).filter(|d| !remaining[*d].is_empty()).collect()
        };
        let prepared: Vec<(usize, Group, Pool, Vec<u8>)> = std::thread::scope(|s| {
            let hs: Vec<_> = movers
                .iter()
                .map(|&d| {
                    let (mut g2, mut pool2) = (g.clone(), pool.clone());
                    let (j, am) = remaining[d][0];
                    let input = notes[d][0].clone();
                    let pk = &pk_upd;
                    let mut r2 = StdRng::seed_from_u64(seed ^ (d as u64) << 32 ^ proofs);
                    s.spawn(move || {
                        let (c, _, _, z) = g2.update(&mut pool2, d + 1, Op::Repay { j, a: am }, &input, 1, rel, memo, &mut r2);
                        let p = Groth16::<Bn254>::prove(pk, c.clone(), &mut r2).unwrap();
                        (d, g2, pool2, enc_update(&c, &z, &p))
                    })
                })
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        proofs += prepared.len() as u64;
        let sent: Vec<String> = prepared.iter().map(|(d, _, _, data)| rpc.send(&accounts[d + 1], &nices, data, 0)).collect();
        let mut accepted = None;
        for (i, tx) in sent.iter().enumerate() {
            let (ok, used, _) = rpc.wait(tx);
            gas += used;
            if ok {
                assert!(accepted.is_none(), "two updates of one group in one round");
                accepted = Some(i);
            } else {
                reverted += 1;
            }
        }
        if let Some(i) = accepted {
            let (d, g2, pool2, _) = prepared.into_iter().nth(i).unwrap();
            g = g2;
            pool = pool2;
            remaining[d].remove(0);
            notes[d].remove(0);
        } else {
            assert!(strategy == "race", "a repayment in turn was rejected");
        }
    }
    assert!(g.balances().iter().all(|x| *x == 0));
    let c: CloseCircuit = g.close();
    let p = Groth16::<Bn254>::prove(&pk_cl, c.clone(), &mut rng).unwrap();
    proofs += 1;
    let data = [selector("close(uint256,uint256[8])"), word(g.gid), proof_words(&p)].concat();
    let (ok, used, end_block) = rpc.wait(&rpc.send(&accounts[1], &nices, &data, 0));
    assert!(ok, "close");
    gas += used;
    println!(
        "{tier},{n},{strategy},{},{},{:.1},{proofs},{reverted},{gas}",
        transfers.len(),
        end_block - start_block,
        start.elapsed().as_secs_f64()
    );
    rpc.call("evm_setIntervalMining", json!([0]));
    rpc.call("evm_setAutomine", json!([true]));
}
