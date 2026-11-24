//! Circuit gadgets: Poseidon, the keystream, range checks and Merkle openings.

use crate::params::{poseidon, Tag};
use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar, poseidon::constraints::PoseidonSpongeVar,
};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

pub type Fv = FpVar<Fr>;
pub type R<T> = Result<T, SynthesisError>;

/// A sponge whose capacity element holds the domain tag, matching `hash::sponge`.
fn sponge(cs: &ConstraintSystemRef<Fr>, tag: Tag) -> PoseidonSpongeVar<Fr> {
    let mut s = PoseidonSpongeVar::<Fr>::new(cs.clone(), poseidon());
    s.state[0] = FpVar::Constant(tag.fr());
    s
}

/// H_tag(xs) in the circuit, matching `hash::h`.
pub fn h(cs: &ConstraintSystemRef<Fr>, tag: Tag, xs: &[Fv]) -> R<Fv> {
    let mut s = sponge(cs, tag);
    s.absorb(&xs.to_vec())?;
    Ok(s.squeeze_field_elements(1)?.remove(0))
}

/// The keystream of length m for key gk and nonce nu, matching `hash::keystream`.
pub fn keystream(cs: &ConstraintSystemRef<Fr>, gk: &Fv, nu: &Fv, m: usize) -> R<Vec<Fv>> {
    let mut s = sponge(cs, Tag::Enc);
    s.absorb(&vec![gk.clone(), nu.clone()])?;
    s.squeeze_field_elements(m)
}

/// Enforces 0 <= x < 2^bits and returns the bits of x, least significant first.
pub fn range_check(cs: &ConstraintSystemRef<Fr>, x: &Fv, bits: usize) -> R<Vec<Boolean<Fr>>> {
    let big = x.value().unwrap_or_default().into_bigint();
    let bs = (0..bits)
        .map(|i| Boolean::new_witness(cs.clone(), || Ok(big.get_bit(i))))
        .collect::<R<Vec<_>>>()?;
    let mut acc = FpVar::Constant(Fr::from(0u64));
    let mut pow = Fr::from(1u64);
    for b in &bs {
        acc += FpVar::from(b.clone()) * pow;
        pow.double_in_place();
    }
    acc.enforce_equal(x)?;
    Ok(bs)
}

/// The root of a Merkle tree from a leaf, the direction bits of its position and the siblings.
pub fn merkle_root(cs: &ConstraintSystemRef<Fr>, leaf: &Fv, bits: &[Boolean<Fr>], path: &[Fv]) -> R<Fv> {
    assert_eq!(bits.len(), path.len());
    let mut cur = leaf.clone();
    for (b, sib) in bits.iter().zip(path) {
        let left = b.select(sib, &cur)?;
        let right = b.select(&cur, sib)?;
        cur = h(cs, Tag::Node, &[left, right])?;
    }
    Ok(cur)
}

pub fn witness(cs: &ConstraintSystemRef<Fr>, v: Fr) -> R<Fv> {
    FpVar::new_witness(cs.clone(), || Ok(v))
}

pub fn witnesses(cs: &ConstraintSystemRef<Fr>, v: &[Fr]) -> R<Vec<Fv>> {
    v.iter().map(|x| witness(cs, *x)).collect()
}

pub fn input(cs: &ConstraintSystemRef<Fr>, v: Fr) -> R<Fv> {
    FpVar::new_input(cs.clone(), || Ok(v))
}

pub fn konst(v: u64) -> Fv {
    FpVar::Constant(Fr::from(v))
}

pub fn pow2(bits: usize) -> Fr {
    let mut p = Fr::from(1u64);
    for _ in 0..bits {
        p.double_in_place();
    }
    p
}

pub fn konst_fr(v: Fr) -> Fv {
    FpVar::Constant(v)
}
