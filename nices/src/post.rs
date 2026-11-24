//! The post relation R_post^N of an off-chain group, (P1)--(P3).

use crate::gadgets::*;
use crate::offchain::{Point, Signature};
use crate::params::{Tag, AMAX_BITS, B_BITS, TMAX_BITS};
use ark_bn254::Fr;
use ark_ec::AffineRepr;
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective, Fr as Scalar};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// The statement (kc, mrootS, ks, t', f, hC, C), N + 10 field elements.
#[derive(Clone, Debug)]
pub struct PostStatement {
    pub kc: Fr,
    pub mroot_s: Fr,
    pub ks: Fr,
    pub t: Fr,
    pub f: Fr,
    pub h_c: Fr,
    pub c: Vec<Fr>,
}

impl PostStatement {
    pub fn inputs(&self) -> Vec<Fr> {
        let mut v = vec![self.kc, self.mroot_s, self.ks, self.t, self.f, self.h_c];
        v.extend_from_slice(&self.c);
        v
    }
}

/// The witness: the group key, n, the membership root, and per slot the signing key, its blinding value, the padding leaf and the signature.  Slots above n carry dummy keys and signatures, which the circuit does not check.
#[derive(Clone, Debug)]
pub struct PostWitness {
    pub gk: Fr,
    pub n: usize,
    pub mroot: Fr,
    pub pk: Vec<Point>,
    pub omega: Vec<Fr>,
    pub pad: Vec<Fr>,
    pub sig: Vec<Signature>,
}

#[derive(Clone, Debug)]
pub struct PostCircuit {
    pub tier: usize,
    pub x: PostStatement,
    pub w: PostWitness,
}

fn point(cs: &ConstraintSystemRef<Fr>, p: Point) -> R<EdwardsVar> {
    EdwardsVar::new_variable_omit_prime_order_check(cs.clone(), || Ok(EdwardsProjective::from(p)), AllocationMode::Witness)
}

impl ConstraintSynthesizer<Fr> for PostCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let n_tier = self.tier;
        let d = n_tier.trailing_zeros() as usize;
        assert_eq!(1 << d, n_tier);
        let (x, w) = (&self.x, &self.w);
        let cs = &cs;
        let zero = konst(0);
        let one = konst(1);

        let kc = input(cs, x.kc)?;
        let mroot_s = input(cs, x.mroot_s)?;
        let ks = input(cs, x.ks)?;
        let t = input(cs, x.t)?;
        let f = input(cs, x.f)?;
        let h_c = input(cs, x.h_c)?;
        assert_eq!(x.c.len(), n_tier + 4);
        let c = x.c.iter().map(|v| input(cs, *v)).collect::<R<Vec<_>>>()?;

        // (P1) kc = H_key(gk), mrootS = H_root(mroot, n), ks = H_ks(sroot, n), 1 <= n <= N: the real slots are the prefix marked by `active`.
        let gk = witness(cs, w.gk)?;
        h(cs, Tag::Key, &[gk.clone()])?.enforce_equal(&kc)?;
        let n = witness(cs, Fr::from(w.n as u64))?;
        let mroot = witness(cs, w.mroot)?;
        h(cs, Tag::Root, &[mroot, n.clone()])?.enforce_equal(&mroot_s)?;
        let active = (0..n_tier).map(|l| Boolean::new_witness(cs.clone(), || Ok(l < w.n))).collect::<R<Vec<_>>>()?;
        active[0].enforce_equal(&Boolean::TRUE)?;
        for l in 1..n_tier {
            active[l - 1].conditional_enforce_equal(&Boolean::TRUE, &active[l])?;
        }
        active.iter().fold(konst(0), |acc, b| acc + FpVar::from(b.clone())).enforce_equal(&n)?;

        // (P2) sroot is the root of the leaves H_sig(l, spk_l, omega_l) for l <= n, and each of them signed H_msg(t', f, hC).
        let pks = w.pk.iter().map(|p| point(cs, *p)).collect::<R<Vec<_>>>()?;
        let mut layer = Vec::with_capacity(n_tier);
        for l in 0..n_tier {
            let omega = witness(cs, w.omega[l])?;
            let pad = witness(cs, w.pad[l])?;
            let leaf = h(cs, Tag::Sig, &[konst(l as u64 + 1), pks[l].x.clone(), pks[l].y.clone(), omega])?;
            layer.push(active[l].select(&leaf, &pad)?);
        }
        while layer.len() > 1 {
            layer = layer.chunks(2).map(|p| h(cs, Tag::Node, &[p[0].clone(), p[1].clone()])).collect::<R<Vec<_>>>()?;
        }
        h(cs, Tag::Ks, &[layer[0].clone(), n])?.enforce_equal(&ks)?;
        let m = h(cs, Tag::Msg, &[t.clone(), f.clone(), h_c.clone()])?;
        let scalar_bits = Scalar::MODULUS_BIT_SIZE as usize;
        let mut bases = Vec::with_capacity(scalar_bits);
        let mut b = Point::generator().into_group();
        for _ in 0..scalar_bits {
            bases.push(b);
            b = b + b;
        }
        for l in 0..n_tier {
            let rp = point(cs, w.sig[l].r)?;
            let sv = w.sig[l].s.into_bigint();
            let s_bits = (0..scalar_bits).map(|i| Boolean::new_witness(cs.clone(), || Ok(sv.get_bit(i)))).collect::<R<Vec<_>>>()?;
            let ch = h(cs, Tag::Chal, &[rp.x.clone(), rp.y.clone(), pks[l].x.clone(), pks[l].y.clone(), m.clone()])?;
            let c_bits = ch.to_bits_le()?;
            let mut lhs = EdwardsVar::zero();
            lhs.precomputed_base_scalar_mul_le(s_bits.iter().zip(bases.iter()))?;
            let rhs = rp + pks[l].scalar_mul_le(c_bits.iter())?;
            lhs.conditional_enforce_equal(&rhs, &active[l])?;
        }

        // (P3) hC = H_st(C); the balances sum to 0, vanish above n, and |b_l| <= t' Amax; 1 <= t' <= Tmax; f is a bit.
        h(cs, Tag::St, &c)?.enforce_equal(&h_c)?;
        (&f * (&f - &one)).enforce_equal(&zero)?;
        range_check(cs, &(&t - &one), TMAX_BITS)?;
        let bound = &t * pow2(AMAX_BITS);
        let keys = keystream(cs, &gk, &c[0], n_tier)?;
        let mut sum = konst(0);
        for l in 0..n_tier {
            let b = &c[1 + l] - &keys[l];
            (&b * FpVar::from(!active[l].clone())).enforce_equal(&zero)?;
            range_check(cs, &(&bound - &b), B_BITS + 2)?;
            range_check(cs, &(&bound + &b), B_BITS + 2)?;
            sum += b;
        }
        sum.enforce_equal(&zero)?;
        Ok(())
    }
}
