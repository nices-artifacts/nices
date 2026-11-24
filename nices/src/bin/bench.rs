//! Constraints, setup, proving and verification time of the three relations.
//!
//! Usage: bench <relation> <tier> <runs>, relation one of update, withdraw, close, insert, post.  Prints one CSV row: relation, tier, public inputs, constraints, setup s, mean proving s, mean verification ms, proving key bytes, peak resident memory MiB.

use ark_bn254::{Bn254, Fr};
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use nices::native::{Group, Op, Pool};
use nices::offchain::OffchainGroup;
use nices::params::MEMO_LEN;
use rand::{rngs::StdRng, SeedableRng};
use std::time::Instant;

fn peak_mib() -> f64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    s.lines()
        .find(|l| l.starts_with("VmHWM:"))
        .and_then(|l| l.split_whitespace().nth(1)?.parse::<f64>().ok())
        .map(|kb| kb / 1024.0)
        .unwrap_or(0.0)
}

fn run<C: ConstraintSynthesizer<Fr> + Clone>(name: &str, tier: usize, runs: usize, c: C, inputs: Vec<Fr>, rng: &mut StdRng) {
    let cs = ConstraintSystem::<Fr>::new_ref();
    c.clone().generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap(), "unsatisfied {name}");
    let constraints = cs.num_constraints();
    let t0 = Instant::now();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(c.clone(), rng).unwrap();
    let setup = t0.elapsed().as_secs_f64();
    let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();
    let mut prove = 0.0;
    let mut verify = 0.0;
    for _ in 0..runs {
        let t0 = Instant::now();
        let proof = Groth16::<Bn254>::prove(&pk, c.clone(), rng).unwrap();
        prove += t0.elapsed().as_secs_f64();
        let t0 = Instant::now();
        assert!(Groth16::<Bn254>::verify_with_processed_vk(&pvk, &inputs, &proof).unwrap());
        verify += t0.elapsed().as_secs_f64();
    }
    println!(
        "{name},{tier},{},{constraints},{setup:.2},{:.3},{:.2},{},{:.0}",
        inputs.len(),
        prove / runs as f64,
        1000.0 * verify / runs as f64,
        pk.compressed_size(),
        peak_mib()
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rel = args.get(1).map(String::as_str).unwrap_or("update");
    let tier: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(8);
    let runs: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(5);
    let mut rng = StdRng::seed_from_u64(7);
    if rel == "post" {
        // A full off-chain group of the tier with one co-signed expense per member.
        let mut og = OffchainGroup::form(tier, tier, 1_000, 10, &mut rng);
        for k in 1..=tier {
            og.expense(k, 10 * tier as u64, &vec![10; tier], &mut rng);
        }
        let c = og.post(false, &mut rng);
        let inputs = c.x.inputs();
        assert_eq!(inputs.len(), tier + 10);
        run("post", tier, runs, c, inputs, &mut rng);
        return;
    }
    let mut pool = Pool::new();
    // A full group of the tier: the circuit size depends on N, not on n.
    let n = tier.max(8);
    let mut g = Group::form(n, n, 1_000, &mut rng);
    let mut notes: Vec<_> = (0..n).map(|l| pool.deposit(1_000_000, g.members[l].nsk, &mut rng)).collect();
    let mut batches = Vec::new();
    while pool.pending() {
        batches.push(pool.insert_batch());
    }
    let memo = [Fr::from(1u64); MEMO_LEN];
    // A first expense so that the measured update decrypts a ciphertext (t > 0).
    let (_, _, chg, _) = g.update(&mut pool, 1, Op::Expense { a: n as u64 * 10, s: vec![10; n] }, &notes[0].clone(), 1, Fr::from(0u64), memo, &mut rng);
    notes[0] = chg;
    match rel {
        "insert" => {
            let c = batches.remove(0);
            let inputs = c.inputs();
            run("insert", 0, runs, c, inputs, &mut rng);
        }
        "update" => {
            pool.commit_note(&notes[1]);
            let relayer = Fr::rand(&mut rng);
            let (c, _, _, _) = g.update(&mut pool, 2, Op::Repay { j: 1, a: 10 }, &notes[1].clone(), 1, relayer, memo, &mut rng);
            let inputs = c.x.inputs();
            assert_eq!(inputs.len(), tier + 18);
            run("update", tier, runs, c, inputs, &mut rng);
        }
        "withdraw" => {
            let c = pool.withdraw(&notes[2].clone(), Fr::from(42u64), 1, Fr::from(5u64));
            let inputs = c.inputs();
            run("withdraw", 0, runs, c, inputs, &mut rng);
        }
        "close" => {
            // Settle every debt to slot 1, then close.
            for l in 2..=n {
                pool.commit_note(&notes[l - 1]);
                let (_, _, chg, _) = g.update(&mut pool, l, Op::Repay { j: 1, a: 10 }, &notes[l - 1].clone(), 1, Fr::from(0u64), memo, &mut rng);
                notes[l - 1] = chg;
            }
            assert!(g.balances().iter().all(|b| *b == 0));
            let c = g.close();
            let inputs = c.inputs();
            run("close", tier, runs, c, inputs, &mut rng);
        }
        _ => panic!("relation: update, withdraw, close, insert or post"),
    }
}
