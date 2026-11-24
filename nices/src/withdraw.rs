//! The withdrawal relation R_wd.

use crate::gadgets::*;
use crate::params::Tag;
use ark_bn254::Fr;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Statement (prt, nf, v, rcpt, fee, rel); witness (nsk, rho, pos, path).
#[derive(Clone, Debug)]
pub struct WithdrawCircuit {
    pub pool_depth: usize,
    pub prt: Fr,
    pub nf: Fr,
    pub v: Fr,
    pub rcpt: Fr,
    pub fee: Fr,
    pub rel: Fr,
    pub nsk: Fr,
    pub rho: Fr,
    pub pos: usize,
    pub path: Vec<Fr>,
}

impl WithdrawCircuit {
    pub fn inputs(&self) -> Vec<Fr> {
        vec![self.prt, self.nf, self.v, self.rcpt, self.fee, self.rel]
    }
}

impl ConstraintSynthesizer<Fr> for WithdrawCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let cs = &cs;
        let prt = input(cs, self.prt)?;
        let nf = input(cs, self.nf)?;
        let v = input(cs, self.v)?;
        let _rcpt = input(cs, self.rcpt)?;
        let _fee = input(cs, self.fee)?;
        let _rel = input(cs, self.rel)?;
        let nsk = witness(cs, self.nsk)?;
        let rho = witness(cs, self.rho)?;
        let pos = witness(cs, Fr::from(self.pos as u64))?;
        let bits = range_check(cs, &pos, self.pool_depth)?;
        let path = witnesses(cs, &self.path)?;
        let addr = h(cs, Tag::Addr, &[nsk.clone()])?;
        let own = h(cs, Tag::Own, &[addr, rho.clone()])?;
        let cm = h(cs, Tag::Cm, &[v, own])?;
        merkle_root(cs, &cm, &bits, &path)?.enforce_equal(&prt)?;
        h(cs, Tag::Nf, &[nsk, rho, pos])?.enforce_equal(&nf)?;
        Ok(())
    }
}
