//! A Merkle tree of fixed depth with H_node, whose empty leaves are 0.

use crate::hash::h;
use crate::params::Tag;
use ark_bn254::Fr;

#[derive(Clone)]
pub struct Tree {
    pub depth: usize,
    pub leaves: Vec<Fr>,
    zeros: Vec<Fr>,
}

impl Tree {
    pub fn new(depth: usize) -> Self {
        let mut zeros = vec![Fr::from(0u64)];
        for i in 0..depth {
            zeros.push(h(Tag::Node, &[zeros[i], zeros[i]]));
        }
        Tree { depth, leaves: Vec::new(), zeros }
    }

    /// Appends a leaf and returns its 0-based position.
    pub fn push(&mut self, leaf: Fr) -> usize {
        assert!(self.leaves.len() < 1 << self.depth);
        self.leaves.push(leaf);
        self.leaves.len() - 1
    }

    fn layers(&self) -> Vec<Vec<Fr>> {
        let mut layers = vec![self.leaves.clone()];
        for lvl in 0..self.depth {
            let cur = &layers[lvl];
            let next = (0..cur.len().div_ceil(2))
                .map(|i| {
                    let l = cur[2 * i];
                    let r = cur.get(2 * i + 1).copied().unwrap_or(self.zeros[lvl]);
                    h(Tag::Node, &[l, r])
                })
                .collect();
            layers.push(next);
        }
        layers
    }

    /// The root of an empty subtree of height i.
    pub fn zero(&self, i: usize) -> Fr {
        self.zeros[i]
    }

    pub fn root(&self) -> Fr {
        self.layers()[self.depth].first().copied().unwrap_or(self.zeros[self.depth])
    }

    /// The siblings of the leaf at 0-based position `pos`, from the leaf up.
    pub fn path(&self, pos: usize) -> Vec<Fr> {
        let layers = self.layers();
        (0..self.depth)
            .map(|lvl| layers[lvl].get((pos >> lvl) ^ 1).copied().unwrap_or(self.zeros[lvl]))
            .collect()
    }
}

/// Recomputes the root natively from a leaf, its 0-based position and its siblings.
pub fn root_from_path(leaf: Fr, pos: usize, path: &[Fr]) -> Fr {
    let mut cur = leaf;
    for (lvl, sib) in path.iter().enumerate() {
        cur = if (pos >> lvl) & 1 == 0 { h(Tag::Node, &[cur, *sib]) } else { h(Tag::Node, &[*sib, cur]) };
    }
    cur
}
