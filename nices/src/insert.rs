//! The batch insertion relation R_ins: the pool tree with old root has an empty aligned subtree at batch index k, and filling it with the batch's leaves gives the new root.

use crate::gadgets::*;
use crate::params::{Tag, BATCH_HEIGHT, BATCH_LEAVES};
use ark_bn254::Fr;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Statement (old root, new root, k, the BATCH_LEAVES leaves padded with zeros); witness: the siblings of the subtree from height BATCH_HEIGHT up.
#[derive(Clone, Debug)]
pub struct InsertCircuit {
    pub pool_depth: usize,
    pub old_root: Fr,
    pub new_root: Fr,
    pub k: usize,
    pub leaves: Vec<Fr>,
    /// The number of leaves that came from the queue; the rest are padding.
    pub real: usize,
    pub path: Vec<Fr>,
    /// The root of an empty subtree of height BATCH_HEIGHT, a constant.
    pub zero: Fr,
}

impl InsertCircuit {
    pub fn inputs(&self) -> Vec<Fr> {
        let mut v = vec![self.old_root, self.new_root, Fr::from(self.k as u64)];
        v.extend_from_slice(&self.leaves);
        v
    }
}

impl ConstraintSynthesizer<Fr> for InsertCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let cs = &cs;
        assert_eq!(self.leaves.len(), BATCH_LEAVES);
        let old_root = input(cs, self.old_root)?;
        let new_root = input(cs, self.new_root)?;
        let k = input(cs, Fr::from(self.k as u64))?;
        let mut level = self.leaves.iter().map(|l| input(cs, *l)).collect::<R<Vec<_>>>()?;
        while level.len() > 1 {
            level = level.chunks(2).map(|p| h(cs, Tag::Node, &[p[0].clone(), p[1].clone()])).collect::<R<Vec<_>>>()?;
        }
        let kbits = range_check(cs, &k, self.pool_depth - BATCH_HEIGHT)?;
        let path = witnesses(cs, &self.path)?;
        merkle_root(cs, &konst_fr(self.zero), &kbits, &path)?.enforce_equal(&old_root)?;
        merkle_root(cs, &level[0], &kbits, &path)?.enforce_equal(&new_root)?;
        Ok(())
    }
}
