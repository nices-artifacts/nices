//! Off-chain groups: EdDSA over Baby Jubjub with a Poseidon challenge, the commitment to the signing keys, off-chain expenses and co-signed states.

use crate::hash::{enc, h};
use crate::native::{fr_i, gid_of, Group};
use crate::params::Tag;
use crate::post::{PostCircuit, PostStatement, PostWitness};
use crate::tree::Tree;
use ark_bn254::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, Fr as Scalar};
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use rand::RngCore;

pub type Point = EdwardsAffine;

#[derive(Clone, Debug)]
pub struct SigKey {
    pub sk: Scalar,
    pub pk: Point,
}

#[derive(Clone, Debug)]
pub struct Signature {
    pub r: Point,
    pub s: Scalar,
}

impl SigKey {
    pub fn gen<R: RngCore>(rng: &mut R) -> Self {
        let sk = Scalar::rand(rng);
        SigKey { sk, pk: (Point::generator() * sk).into_affine() }
    }

    /// s = r + c sk, with R = r G and c = H_chal(R, A, m) read as a scalar.
    pub fn sign<R: RngCore>(&self, m: Fr, rng: &mut R) -> Signature {
        let r = Scalar::rand(rng);
        let rp = (Point::generator() * r).into_affine();
        Signature { r: rp, s: r + to_scalar(challenge(&rp, &self.pk, m)) * self.sk }
    }
}

/// The challenge H_chal(R_x, R_y, A_x, A_y, m).
pub fn challenge(r: &Point, a: &Point, m: Fr) -> Fr {
    h(Tag::Chal, &[r.x, r.y, a.x, a.y, m])
}

pub fn to_scalar(c: Fr) -> Scalar {
    Scalar::from_le_bytes_mod_order(&c.into_bigint().to_bytes_le())
}

/// s G = R + c A.
pub fn verify(pk: &Point, m: Fr, sig: &Signature) -> bool {
    Point::generator() * sig.s == sig.r + *pk * to_scalar(challenge(&sig.r, pk, m))
}

/// The message H_msg(t, f, hC) that a member signs for the state (t, f, C).
pub fn msg(t: u64, f: bool, h_c: Fr) -> Fr {
    h(Tag::Msg, &[Fr::from(t), Fr::from(f as u64), h_c])
}

pub fn sig_leaf(l: usize, pk: &Point, omega: Fr) -> Fr {
    h(Tag::Sig, &[Fr::from(l as u64), pk.x, pk.y, omega])
}

/// An off-chain group: a group of Section 4 with signing keys, their commitment ks and the challenge period.
#[derive(Clone)]
pub struct OffchainGroup {
    pub g: Group,
    pub keys: Vec<SigKey>,
    pub omega: Vec<Fr>,
    /// The leaves of the slots above n.
    pub pad: Vec<Fr>,
    pub stree: Tree,
}

impl OffchainGroup {
    pub fn form<R: RngCore>(n: usize, tier: usize, h_end: u64, dch: u64, rng: &mut R) -> Self {
        let mut g = Group::form(n, tier, h_end, rng);
        let keys: Vec<SigKey> = (0..n).map(|_| SigKey::gen(rng)).collect();
        let omega: Vec<Fr> = (0..n).map(|_| Fr::rand(rng)).collect();
        let pad: Vec<Fr> = (n..tier).map(|_| Fr::rand(rng)).collect();
        let mut stree = Tree::new(tier.trailing_zeros() as usize);
        for l in 0..tier {
            stree.push(if l < n { sig_leaf(l + 1, &keys[l].pk, omega[l]) } else { pad[l - n] });
        }
        g.ks = h(Tag::Ks, &[stree.root(), Fr::from(n as u64)]);
        g.dch = dch;
        g.gid = gid_of(g.kc, g.mroot_s, tier, h_end, g.ks, dch);
        OffchainGroup { g, keys, omega, pad, stree }
    }

    /// Member k (1-based) records an expense off-chain: the next state, which every correct member signs.
    pub fn expense<R: RngCore>(&mut self, k: usize, a: u64, s: &[u64], rng: &mut R) {
        let g = &mut self.g;
        let n_tier = g.tier;
        assert!(s.len() <= g.n() && s.iter().sum::<u64>() == a);
        let mut b = g.balances();
        b[k - 1] += a as i128;
        for (l, v) in s.iter().enumerate() {
            b[l] -= *v as i128;
        }
        let mut x: Vec<Fr> = b.iter().map(|v| fr_i(*v)).collect();
        x.extend_from_slice(&[Fr::from(k as u64), Fr::from(a), Fr::zero()]);
        let c = enc(g.gk, &x, Fr::rand(rng));
        assert_eq!(c.len(), n_tier + 4);
        g.t += 1;
        g.h_c = h(Tag::St, &c);
        g.c = c;
        g.b = b;
    }

    /// The post of the current state with flag f, signed by every member.
    pub fn post<R: RngCore>(&self, f: bool, rng: &mut R) -> PostCircuit {
        let g = &self.g;
        let n_tier = g.tier;
        let n = g.n();
        let m = msg(g.t, f, g.h_c);
        let sigs: Vec<Signature> = self.keys.iter().map(|k| k.sign(m, rng)).collect();
        assert!(sigs.iter().zip(&self.keys).all(|(s, k)| verify(&k.pk, m, s)));
        let gen = Point::generator();
        let dummy = Signature { r: gen, s: Scalar::zero() };
        PostCircuit {
            tier: n_tier,
            x: PostStatement { kc: g.kc, mroot_s: g.mroot_s, ks: g.ks, t: Fr::from(g.t), f: Fr::from(f as u64), h_c: g.h_c, c: g.c.clone() },
            w: PostWitness {
                gk: g.gk,
                n,
                mroot: g.tree.root(),
                pk: (0..n_tier).map(|l| if l < n { self.keys[l].pk } else { gen }).collect(),
                omega: (0..n_tier).map(|l| if l < n { self.omega[l] } else { Fr::zero() }).collect(),
                pad: (0..n_tier).map(|l| if l < n { Fr::zero() } else { self.pad[l - n] }).collect(),
                sig: (0..n_tier).map(|l| if l < n { sigs[l].clone() } else { dummy.clone() }).collect(),
            },
        }
    }
}
