//! End-to-end runs of the protocol, checked against the ideal bookkeeping, and the rejection of invalid updates.

use ark_bn254::Fr;
use ark_ff::UniformRand;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use nices::native::{Group, Note, Op, Pool};
use nices::params::MEMO_LEN;
use rand::{rngs::StdRng, SeedableRng};

fn satisfied<C: ConstraintSynthesizer<Fr>>(c: C) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    c.generate_constraints(cs.clone()).unwrap();
    cs.is_satisfied().unwrap()
}

fn memo() -> [Fr; MEMO_LEN] {
    [Fr::from(7u64); MEMO_LEN]
}

struct Setup {
    rng: StdRng,
    pool: Pool,
    g: Group,
    notes: Vec<Note>,
}

fn setup(n: usize, tier: usize) -> Setup {
    let mut rng = StdRng::seed_from_u64(1);
    let mut pool = Pool::new();
    let g = Group::form(n, tier, 1_000, &mut rng);
    let notes = (0..n).map(|l| pool.deposit(1_000_000, g.members[l].nsk, &mut rng)).collect();
    while pool.pending() {
        assert!(satisfied(pool.insert_batch()));
    }
    Setup { rng, pool, g, notes }
}

impl Setup {
    fn op(&mut self, k: usize, op: Op) -> bool {
        let input = self.notes[k - 1].clone();
        for c in self.pool.commit_note(&input) {
            assert!(satisfied(c));
        }
        let rel = Fr::rand(&mut self.rng);
        let (c, _out, chg, _z) = self.g.update(&mut self.pool, k, op, &input, 10, rel, memo(), &mut self.rng);
        self.notes[k - 1] = chg;
        satisfied(c)
    }
}

#[test]
fn expenses_and_repayments() {
    let mut s = setup(3, 8);
    assert!(s.op(1, Op::Expense { a: 90, s: vec![30, 30, 30] }));
    assert!(s.op(2, Op::Expense { a: 31, s: vec![10, 11, 10] }));
    assert_eq!(s.g.balances(), s.g.b);
    assert_eq!(s.g.balances()[..3], [50, -10, -40]);
    assert!(s.op(3, Op::Repay { j: 1, a: 40 }));
    assert!(s.op(2, Op::Repay { j: 1, a: 10 }));
    assert_eq!(s.g.balances(), vec![0; 8]);
    assert!(satisfied(s.g.close()));
}

#[test]
fn repayment_above_debt_is_rejected() {
    let mut s = setup(3, 8);
    assert!(s.op(1, Op::Expense { a: 90, s: vec![30, 30, 30] }));
    assert!(!s.op(2, Op::Repay { j: 1, a: 31 }));
}

#[test]
fn repayment_to_a_debtor_is_rejected() {
    let mut s = setup(3, 8);
    assert!(s.op(1, Op::Expense { a: 90, s: vec![30, 30, 30] }));
    assert!(!s.op(2, Op::Repay { j: 3, a: 1 }));
}

#[test]
fn shares_must_sum_to_the_amount() {
    let mut s = setup(3, 8);
    assert!(!s.op(1, Op::Expense { a: 90, s: vec![30, 30, 29] }));
}

#[test]
fn padding_slots_are_never_charged() {
    let mut s = setup(3, 8);
    assert!(!s.op(1, Op::Expense { a: 90, s: vec![30, 30, 20, 10] }));
}

#[test]
fn settlement_period_admits_only_repayments() {
    let mut s = setup(3, 8);
    assert!(s.op(1, Op::Expense { a: 90, s: vec![30, 30, 30] }));
    s.g.settling = true;
    assert!(!s.op(1, Op::Expense { a: 3, s: vec![1, 1, 1] }));
    let mut s = setup(3, 8);
    assert!(s.op(1, Op::Expense { a: 90, s: vec![30, 30, 30] }));
    s.g.settling = true;
    assert!(s.op(2, Op::Repay { j: 1, a: 30 }));
}

#[test]
fn close_requires_zero_balances() {
    let mut s = setup(2, 8);
    assert!(s.op(1, Op::Expense { a: 10, s: vec![5, 5] }));
    assert!(!satisfied(s.g.close()));
}

#[test]
fn full_and_partial_batches() {
    let mut rng = StdRng::seed_from_u64(3);
    let mut pool = Pool::new();
    let notes: Vec<Note> = (0..70).map(|_| pool.deposit(5, Fr::rand(&mut rng), &mut rng)).collect();
    assert_eq!(pool.sealed.len(), 2);
    let mut cs = Vec::new();
    while pool.pending() {
        cs.push(pool.insert_batch());
    }
    assert_eq!(cs.iter().map(|c| c.real).collect::<Vec<_>>(), vec![64, 64, 12]);
    assert!(notes.iter().all(|n| pool.committed(n)));
    for c in cs {
        assert!(satisfied(c));
    }
    // A wrong new root is rejected.
    pool.deposit(5, Fr::rand(&mut rng), &mut rng);
    let mut c = pool.insert_batch();
    c.new_root += Fr::from(1u64);
    assert!(!satisfied(c));
}

#[test]
fn withdrawal() {
    let mut s = setup(2, 8);
    let n = s.notes[0].clone();
    let rel = Fr::rand(&mut s.rng);
    let c = s.pool.withdraw(&n, Fr::from(42u64), 5, rel);
    assert!(satisfied(c));
}
