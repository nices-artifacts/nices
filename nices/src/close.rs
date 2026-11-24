//! The close relation R_cl^N.

use crate::gadgets::*;
use crate::params::Tag;
use ark_bn254::Fr;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Statement (kc, hC); witness (gk, C): kc = H_key(gk), hC = H_st(C), and the N balances of C are zero.
#[derive(Clone, Debug)]
pub struct CloseCircuit {
    pub tier: usize,
    pub kc: Fr,
    pub h_c: Fr,
    pub gk: Fr,
    pub c: Vec<Fr>,
}

impl CloseCircuit {
    pub fn inputs(&self) -> Vec<Fr> {
        vec![self.kc, self.h_c]
    }
}

impl ConstraintSynthesizer<Fr> for CloseCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let cs = &cs;
        let kc = input(cs, self.kc)?;
        let h_c = input(cs, self.h_c)?;
        let gk = witness(cs, self.gk)?;
        assert_eq!(self.c.len(), self.tier + 4);
        let c = witnesses(cs, &self.c)?;
        h(cs, Tag::Key, &[gk.clone()])?.enforce_equal(&kc)?;
        h(cs, Tag::St, &c)?.enforce_equal(&h_c)?;
        let ks = keystream(cs, &gk, &c[0], self.tier)?;
        for l in 0..self.tier {
            c[1 + l].enforce_equal(&ks[l])?;
        }
        Ok(())
    }
}
