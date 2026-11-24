//! Off-chain groups: co-signed states, posts, and the on-chain continuation from a posted state.

use ark_bn254::Fr;
use ark_ec::AffineRepr;
use ark_ed_on_bn254::{EdwardsAffine, Fr as Scalar};
use ark_ff::{One, UniformRand};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use nices::native::{Op, Pool};
use nices::offchain::OffchainGroup;
use nices::params::MEMO_LEN;
use rand::{rngs::StdRng, SeedableRng};

fn satisfied<C: ConstraintSynthesizer<Fr>>(c: C) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    c.generate_constraints(cs.clone()).unwrap();
    cs.is_satisfied().unwrap()
}

#[test]
fn generator_in_subgroup() {
    assert!(EdwardsAffine::generator().is_in_correct_subgroup_assuming_on_curve());
}

#[test]
fn post_and_continue_on_chain() {
    let mut rng = StdRng::seed_from_u64(3);
    let mut og = OffchainGroup::form(3, 8, 1_000, 10, &mut rng);
    og.expense(1, 90, &[30, 30, 30], &mut rng);
    og.expense(2, 30, &[10, 10, 10], &mut rng);
    assert_eq!(og.g.balances()[..3], [50, -10, -40]);
    assert!(satisfied(og.post(false, &mut rng)));
    assert!(satisfied(og.post(true, &mut rng)));
    // The debtors repay on-chain from the posted final state.
    let mut pool = Pool::new();
    let notes: Vec<_> = (0..3).map(|l| pool.deposit(1_000, og.g.members[l].nsk, &mut rng)).collect();
    while pool.pending() {
        pool.insert_batch();
    }
    let mut g = og.g.clone();
    g.settling = true;
    let memo = [Fr::from(1u64); MEMO_LEN];
    let (c, _, _, _) = g.update(&mut pool, 3, Op::Repay { j: 1, a: 40 }, &notes[2], 1, Fr::from(9u64), memo, &mut rng);
    assert!(satisfied(c));
    let (c, _, _, _) = g.update(&mut pool, 2, Op::Repay { j: 1, a: 10 }, &notes[1], 1, Fr::from(9u64), memo, &mut rng);
    assert!(satisfied(c));
    assert!(g.balances().iter().all(|b| *b == 0));
    assert!(satisfied(g.close()));
}

#[test]
fn rejects_missing_or_forged_signature() {
    let mut rng = StdRng::seed_from_u64(4);
    let mut og = OffchainGroup::form(3, 8, 1_000, 10, &mut rng);
    og.expense(1, 60, &[20, 20, 20], &mut rng);
    let mut p = og.post(false, &mut rng);
    p.w.sig[1].s += Scalar::one();
    assert!(!satisfied(p));
    // A state signed for another sequence number.
    let mut p = og.post(false, &mut rng);
    p.x.t = Fr::from(2u64);
    assert!(!satisfied(p));
    // A claim of fewer members, which would skip a signature.
    let mut p = og.post(false, &mut rng);
    p.w.n = 2;
    assert!(!satisfied(p));
}

#[test]
fn rejects_balances_out_of_bound_or_unbalanced() {
    let mut rng = StdRng::seed_from_u64(5);
    let mut og = OffchainGroup::form(2, 8, 1_000, 10, &mut rng);
    og.expense(1, 100, &[50, 50], &mut rng);
    // A state that claims t' = 0.
    let mut p = og.post(false, &mut rng);
    p.x.t = Fr::from(0u64);
    assert!(!satisfied(p));
    // A ciphertext whose balances do not sum to zero.
    let mut p = og.post(false, &mut rng);
    p.x.c[1] += Fr::from(1u64);
    assert!(!satisfied(p));
    let _ = Fr::rand(&mut rng);
}
