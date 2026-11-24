//! Native Poseidon hashing and the counter-mode encryption under the group key.

use crate::params::{poseidon, Tag};
use ark_bn254::Fr;
use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};

/// A sponge whose capacity element holds the domain tag.
fn sponge(tag: Tag) -> PoseidonSponge<Fr> {
    let mut s = PoseidonSponge::<Fr>::new(poseidon());
    s.state[0] = tag.fr();
    s
}

/// H_tag(xs): the sponge with tag `tag` absorbs the inputs and squeezes one element.  Two inputs take one permutation.
pub fn h(tag: Tag, xs: &[Fr]) -> Fr {
    let mut s = sponge(tag);
    s.absorb(&xs.to_vec());
    s.squeeze_field_elements::<Fr>(1)[0]
}

/// The keystream H_enc(gk, nu, 1), ..., H_enc(gk, nu, m), squeezed from one sponge.
pub fn keystream(gk: Fr, nu: Fr, m: usize) -> Vec<Fr> {
    let mut s = sponge(Tag::Enc);
    s.absorb(&vec![gk, nu]);
    s.squeeze_field_elements::<Fr>(m)
}

/// Enc_gk(x; nu) = (nu, x_1 + k_1, ..., x_m + k_m).
pub fn enc(gk: Fr, x: &[Fr], nu: Fr) -> Vec<Fr> {
    let ks = keystream(gk, nu, x.len());
    std::iter::once(nu).chain(x.iter().zip(ks).map(|(a, b)| *a + b)).collect()
}

/// The first m entries of Dec_gk(c).
pub fn dec(gk: Fr, c: &[Fr], m: usize) -> Vec<Fr> {
    let ks = keystream(gk, c[0], m);
    c[1..=m].iter().zip(ks).map(|(a, b)| *a - b).collect()
}
