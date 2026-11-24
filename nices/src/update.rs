//! The update relation R_upd^N of Figure 1, constraints (R1)--(R6).

use crate::gadgets::*;
use crate::params::{Tag, AMAX_BITS, B_BITS, VALUE_BITS};
use ark_bn254::Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// The statement of an update, in the order of its public inputs.
#[derive(Clone, Debug)]
pub struct UpdateStatement {
    pub gid: Fr,
    pub t: Fr,
    pub sigma: Fr,
    pub kc: Fr,
    pub mroot_s: Fr,
    pub h_c: Fr,
    pub h_cn: Fr,
    /// The new ciphertext: the nonce, N balances and the three audit tags.
    pub c_new: Vec<Fr>,
    pub hz: Fr,
    pub prt: Fr,
    pub nf: Fr,
    pub cm_out: Fr,
    pub cm_chg: Fr,
    pub fee: Fr,
    pub rel: Fr,
}

impl UpdateStatement {
    /// The public inputs, N + 18 field elements.
    pub fn inputs(&self) -> Vec<Fr> {
        let mut v = vec![self.gid, self.t, self.sigma, self.kc, self.mroot_s, self.h_c, self.h_cn];
        v.extend_from_slice(&self.c_new);
        v.extend_from_slice(&[self.hz, self.prt, self.nf, self.cm_out, self.cm_chg, self.fee, self.rel]);
        v
    }
}

/// The witness of an update.  Slots k and j are 1-based; the note position is 0-based.
#[derive(Clone, Debug)]
pub struct UpdateWitness {
    pub gk: Fr,
    pub n: usize,
    pub mroot: Fr,
    pub k: usize,
    pub idv: Fr,
    pub addr_k: Fr,
    pub path_k: Vec<Fr>,
    pub j: usize,
    pub c_j: Fr,
    pub addr_j: Fr,
    pub path_j: Vec<Fr>,
    pub mu: bool,
    pub a: Fr,
    pub s: Vec<Fr>,
    pub c_old: Vec<Fr>,
    pub v: Fr,
    pub nsk: Fr,
    pub rho: Fr,
    pub pos: usize,
    pub path_in: Vec<Fr>,
    pub v_chg: Fr,
    pub addr_chg: Fr,
    pub rho_chg: Fr,
    pub addr_out: Fr,
}

#[derive(Clone, Debug)]
pub struct UpdateCircuit {
    /// The tier N.
    pub tier: usize,
    pub pool_depth: usize,
    pub x: UpdateStatement,
    pub w: UpdateWitness,
}

impl ConstraintSynthesizer<Fr> for UpdateCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let n_tier = self.tier;
        let d = n_tier.trailing_zeros() as usize;
        assert_eq!(1 << d, n_tier);
        let (x, w) = (&self.x, &self.w);
        let cs = &cs;
        let zero = konst(0);
        let one = konst(1);

        // Statement.
        let _gid = input(cs, x.gid)?;
        let t = input(cs, x.t)?;
        let sigma = input(cs, x.sigma)?;
        let kc = input(cs, x.kc)?;
        let mroot_s = input(cs, x.mroot_s)?;
        let h_c = input(cs, x.h_c)?;
        let h_cn = input(cs, x.h_cn)?;
        assert_eq!(x.c_new.len(), n_tier + 4);
        let c_new = x.c_new.iter().map(|v| input(cs, *v)).collect::<R<Vec<_>>>()?;
        // gid, hz and rel are not constrained: the R1CS-to-QAP reduction of arkworks adds one constraint per public input, which binds them to the proof.
        let _hz = input(cs, x.hz)?;
        let prt = input(cs, x.prt)?;
        let nf = input(cs, x.nf)?;
        let cm_out = input(cs, x.cm_out)?;
        let cm_chg = input(cs, x.cm_chg)?;
        let fee = input(cs, x.fee)?;
        let _rel = input(cs, x.rel)?;

        // (R1) Key.
        let gk = witness(cs, w.gk)?;
        h(cs, Tag::Key, &[gk.clone()])?.enforce_equal(&kc)?;

        // (R2) Membership and slot binding.  The slots k and j are one-hot vectors e and f over [N], the real slots are the prefix of length n marked by `active`, and k, j <= n.
        let n = witness(cs, Fr::from(w.n as u64))?;
        let mroot = witness(cs, w.mroot)?;
        h(cs, Tag::Root, &[mroot.clone(), n.clone()])?.enforce_equal(&mroot_s)?;
        let onehot = |slot: usize| -> R<Vec<Boolean<Fr>>> {
            (0..n_tier).map(|l| Boolean::new_witness(cs.clone(), || Ok(l + 1 == slot))).collect()
        };
        let e = onehot(w.k)?;
        let f = onehot(w.j)?;
        let active = (0..n_tier)
            .map(|l| Boolean::new_witness(cs.clone(), || Ok(l < w.n)))
            .collect::<R<Vec<_>>>()?;
        let sum = |bs: &[Boolean<Fr>]| bs.iter().fold(konst(0), |acc, b| acc + FpVar::from(b.clone()));
        let index = |bs: &[Boolean<Fr>]| {
            bs.iter().enumerate().fold(konst(0), |acc, (l, b)| acc + FpVar::from(b.clone()) * Fr::from(l as u64 + 1))
        };
        sum(&e).enforce_equal(&one)?;
        sum(&f).enforce_equal(&one)?;
        sum(&active).enforce_equal(&n)?;
        for l in 1..n_tier {
            active[l - 1].conditional_enforce_equal(&Boolean::TRUE, &active[l])?;
        }
        let k = index(&e);
        let j = index(&f);
        range_check(cs, &(&n - &k), d + 1)?;
        range_check(cs, &(&n - &j), d + 1)?;

        let kbits = range_check(cs, &(&k - &one), d)?;
        let idv = witness(cs, w.idv)?;
        let addr_k = witness(cs, w.addr_k)?;
        let path_k = witnesses(cs, &w.path_k)?;
        let c_k = h(cs, Tag::Id, &[idv])?;
        let leaf_k = h(cs, Tag::Leaf, &[k.clone(), c_k, addr_k])?;
        merkle_root(cs, &leaf_k, &kbits, &path_k)?.enforce_equal(&mroot)?;

        let jbits = range_check(cs, &(&j - &one), d)?;
        let c_j = witness(cs, w.c_j)?;
        let addr_j = witness(cs, w.addr_j)?;
        let path_j = witnesses(cs, &w.path_j)?;
        let leaf_j = h(cs, Tag::Leaf, &[j.clone(), c_j, addr_j.clone()])?;
        merkle_root(cs, &leaf_j, &jbits, &path_j)?.enforce_equal(&mroot)?;

        // (R3) Operation.  sigma is a bit, and sigma = 1 forces a repayment.
        let mu_b = Boolean::new_witness(cs.clone(), || Ok(w.mu))?;
        let mu = FpVar::from(mu_b);
        let not_mu = &one - &mu;
        (&sigma * (&sigma - &one)).enforce_equal(&zero)?;
        (&sigma * &not_mu).enforce_equal(&zero)?;

        let a = witness(cs, w.a)?;
        range_check(cs, &(&a - &one), B_BITS)?;
        // Expense: 1 <= a <= Amax.
        range_check(cs, &(&not_mu * (&a - &one)), AMAX_BITS)?;
        assert_eq!(w.s.len(), n_tier);
        let s = witnesses(cs, &w.s)?;
        let mut s_sum = konst(0);
        for l in 0..n_tier {
            // Expense: 0 <= s_l <= Amax.  Both: s_l = 0 for padding slots.  Repayment: s = a e_j.
            range_check(cs, &(&not_mu * &s[l]), AMAX_BITS + 1)?;
            (&s[l] * FpVar::from(!active[l].clone())).enforce_equal(&zero)?;
            let a_f = &a * FpVar::from(f[l].clone());
            (&mu * (&s[l] - a_f)).enforce_equal(&zero)?;
            s_sum += &s[l];
        }
        s_sum.enforce_equal(&a)?;
        // Repayment: k != j.
        let mut overlap = konst(0);
        for l in 0..n_tier {
            overlap += FpVar::from(e[l].clone()) * FpVar::from(f[l].clone());
        }
        (&mu * overlap).enforce_equal(&zero)?;

        // (R4) Balances.  If t = 0 the balances are zero; otherwise the witness ciphertext is the stored one.
        assert_eq!(w.c_old.len(), n_tier + 4);
        let c_old = witnesses(cs, &w.c_old)?;
        let t_zero = t.is_eq(&zero)?;
        h(cs, Tag::St, &c_old)?.conditional_enforce_equal(&h_c, &!t_zero.clone())?;
        let ks_old = keystream(cs, &gk, &c_old[0], n_tier)?;
        let b = (0..n_tier)
            .map(|l| t_zero.select(&zero, &(&c_old[1 + l] - &ks_old[l])))
            .collect::<R<Vec<_>>>()?;
        let mut b_k = konst(0);
        let mut b_j = konst(0);
        for l in 0..n_tier {
            b_k += FpVar::from(e[l].clone()) * &b[l];
            b_j += FpVar::from(f[l].clone()) * &b[l];
        }
        // Repayment: |b_k|, |b_j| < B, 1 <= a <= -b_k and a <= b_j.
        let bb = pow2(B_BITS);
        range_check(cs, &(&mu * (&b_k + (bb - Fr::from(1u64)))), B_BITS + 1)?;
        range_check(cs, &(&mu * ((&b_j * Fr::from(-1i64)) + (bb - Fr::from(1u64)))), B_BITS + 1)?;
        range_check(cs, &(&mu * ((&b_k * Fr::from(-1i64)) - &a)), B_BITS + 1)?;
        range_check(cs, &(&mu * (&b_j - &a)), B_BITS + 1)?;
        let b_new = (0..n_tier)
            .map(|l| &b[l] + &a * FpVar::from(e[l].clone()) - &s[l])
            .collect::<Vec<_>>();

        // (R5) New ciphertext with the audit tags (k, a, mu j).
        let ks_new = keystream(cs, &gk, &c_new[0], n_tier + 3)?;
        let tags = [k.clone(), a.clone(), &mu * &j];
        for l in 0..n_tier {
            c_new[1 + l].enforce_equal(&(&b_new[l] + &ks_new[l]))?;
        }
        for i in 0..3 {
            c_new[1 + n_tier + i].enforce_equal(&(&tags[i] + &ks_new[n_tier + i]))?;
        }
        h(cs, Tag::St, &c_new)?.enforce_equal(&h_cn)?;

        // (R6) Pool.
        let v = witness(cs, w.v)?;
        let nsk = witness(cs, w.nsk)?;
        let rho = witness(cs, w.rho)?;
        let pos = witness(cs, Fr::from(w.pos as u64))?;
        let pos_bits = range_check(cs, &pos, self.pool_depth)?;
        let path_in = witnesses(cs, &w.path_in)?;
        let addr = h(cs, Tag::Addr, &[nsk.clone()])?;
        let own = h(cs, Tag::Own, &[addr, rho.clone()])?;
        let cm = h(cs, Tag::Cm, &[v.clone(), own])?;
        merkle_root(cs, &cm, &pos_bits, &path_in)?.enforce_equal(&prt)?;
        h(cs, Tag::Nf, &[nsk, rho, pos])?.enforce_equal(&nf)?;
        let v_chg = witness(cs, w.v_chg)?;
        range_check(cs, &v_chg, VALUE_BITS)?;
        range_check(cs, &fee, VALUE_BITS)?;
        let t_out = &mu * &a;
        v.enforce_equal(&(&t_out + &fee + &v_chg))?;
        let rho_out = h(cs, Tag::Rho, &[gk.clone(), nf.clone()])?;
        let addr_out = witness(cs, w.addr_out)?;
        (&mu * (&addr_out - &addr_j)).enforce_equal(&zero)?;
        let own_out = h(cs, Tag::Own, &[addr_out, rho_out])?;
        h(cs, Tag::Cm, &[t_out, own_out])?.enforce_equal(&cm_out)?;
        let addr_chg = witness(cs, w.addr_chg)?;
        let rho_chg = witness(cs, w.rho_chg)?;
        let own_chg = h(cs, Tag::Own, &[addr_chg, rho_chg])?;
        h(cs, Tag::Cm, &[v_chg, own_chg])?.enforce_equal(&cm_chg)?;
        Ok(())
    }
}
