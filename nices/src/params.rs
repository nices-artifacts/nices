//! Public parameters: the Poseidon instance, the bounds and the tiers.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use std::sync::OnceLock;

/// A single expense is at most 2^32 units.
pub const AMAX_BITS: usize = 32;
/// A group accepts at most 2^32 updates.
pub const TMAX_BITS: usize = 32;
/// The bound B = Tmax * Amax = 2^64 on every balance.
pub const B_BITS: usize = AMAX_BITS + TMAX_BITS;
/// Fees and change are below 2^64.
pub const VALUE_BITS: usize = 64;
/// Length M of the memo in field elements, 31 bytes each.
pub const MEMO_LEN: usize = 4;
/// Depth D of the note pool tree.
pub const POOL_DEPTH: usize = 32;
/// A batch of the pool queue holds at most 32 pairs of leaves, and occupies an aligned subtree of 64 leaves.
pub const BATCH_PAIRS: usize = 32;
pub const BATCH_LEAVES: usize = 2 * BATCH_PAIRS;
pub const BATCH_HEIGHT: usize = 6;
/// The size tiers N.
pub const TIERS: [usize; 4] = [8, 16, 32, 64];

/// Poseidon over the scalar field of BN254: width 3, rate 2, x^5, 8 full and 57 partial rounds.
pub fn poseidon() -> &'static PoseidonConfig<Fr> {
    static P: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    P.get_or_init(|| {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(254, 2, 8, 57, 0);
        PoseidonConfig::new(8, 57, 5, mds, ark, 2, 1)
    })
}

/// Domain-separation tags: the sponge of H_tag starts with its tag in the capacity element.
#[derive(Clone, Copy, Debug)]
pub enum Tag {
    Key = 1,
    Enc = 2,
    Rho = 3,
    Id = 4,
    Addr = 5,
    Leaf = 6,
    Node = 7,
    Root = 8,
    St = 9,
    Cm = 10,
    Own = 11,
    Nf = 12,
    Ks = 13,
    Sig = 14,
    Msg = 15,
    Chal = 16,
}

impl Tag {
    pub fn fr(self) -> Fr {
        Fr::from(self as u64)
    }
}
