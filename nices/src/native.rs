//! A native model of the contract, a group and the note pool, which produces the statements and witnesses of the three relations.

use crate::close::CloseCircuit;
use crate::hash::{dec, enc, h, keystream};
use crate::insert::InsertCircuit;
use crate::params::{Tag, BATCH_HEIGHT, BATCH_LEAVES, MEMO_LEN, POOL_DEPTH};
use crate::tree::Tree;
use crate::update::{UpdateCircuit, UpdateStatement, UpdateWitness};
use crate::withdraw::WithdrawCircuit;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use rand::RngCore;
use std::collections::{HashSet, VecDeque};
use tiny_keccak::{Hasher, Keccak};

/// Signed integer to field element.
pub fn fr_i(x: i128) -> Fr {
    if x >= 0 { Fr::from(x as u128) } else { -Fr::from((-x) as u128) }
}

/// Field element to signed integer, for |x| < 2^127.
pub fn i_fr(x: Fr) -> i128 {
    let big = x.into_bigint();
    let small = |b: &[u64]| b[2] == 0 && b[3] == 0 && b[1] >> 63 == 0;
    if small(big.as_ref()) {
        (big.as_ref()[0] as i128) | ((big.as_ref()[1] as i128) << 64)
    } else {
        let nb = (-x).into_bigint();
        -((nb.as_ref()[0] as i128) | ((nb.as_ref()[1] as i128) << 64))
    }
}

/// keccak256 of the 32-byte big-endian encodings, reduced mod r, as the contract computes it.
pub fn keccak_fr(xs: &[Fr]) -> Fr {
    let mut k = Keccak::v256();
    for x in xs {
        k.update(&x.into_bigint().to_bytes_be());
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    Fr::from_be_bytes_mod_order(&out)
}

#[derive(Clone, Debug)]
pub struct Note {
    pub v: u64,
    pub nsk: Fr,
    pub rho: Fr,
    pub pos: usize,
}

impl Note {
    pub fn addr(&self) -> Fr {
        h(Tag::Addr, &[self.nsk])
    }
}

pub fn commit(v: u64, addr: Fr, rho: Fr) -> Fr {
    h(Tag::Cm, &[Fr::from(v), h(Tag::Own, &[addr, rho])])
}

/// The contract's pool: the committed tree, the queue of pending leaves in batches, and the spent nullifiers.
#[derive(Clone)]
pub struct Pool {
    pub tree: Tree,
    /// Sealed batches, each of BATCH_LEAVES leaves, oldest first.
    pub sealed: VecDeque<Vec<Fr>>,
    /// The open batch and its index.
    pub open: Vec<Fr>,
    pub open_batch: usize,
    pub spent: HashSet<Fr>,
}

impl Pool {
    pub fn new() -> Self {
        Pool { tree: Tree::new(POOL_DEPTH), sealed: VecDeque::new(), open: Vec::new(), open_batch: 0, spent: HashSet::new() }
    }

    /// Appends a pair of leaves to the open batch and returns the position of the first.
    pub fn queue_pair(&mut self, l: Fr, r: Fr) -> usize {
        let pos = BATCH_LEAVES * self.open_batch + self.open.len();
        self.open.push(l);
        self.open.push(r);
        if self.open.len() == BATCH_LEAVES {
            self.sealed.push_back(std::mem::take(&mut self.open));
            self.open_batch += 1;
        }
        pos
    }

    pub fn committed(&self, n: &Note) -> bool {
        n.pos < self.tree.leaves.len()
    }

    pub fn pending(&self) -> bool {
        !self.sealed.is_empty() || !self.open.is_empty()
    }

    /// InsertBatch: inserts the oldest pending batch, sealing the open one if no sealed batch waits, and returns the statement and witness of R_ins.
    pub fn insert_batch(&mut self) -> InsertCircuit {
        let leaves = match self.sealed.pop_front() {
            Some(b) => b,
            None => {
                assert!(!self.open.is_empty());
                self.open_batch += 1;
                std::mem::take(&mut self.open)
            }
        };
        let real = leaves.len();
        let start = self.tree.leaves.len();
        assert_eq!(start % BATCH_LEAVES, 0);
        let old_root = self.tree.root();
        let mut padded = leaves;
        padded.resize(BATCH_LEAVES, Fr::zero());
        for l in &padded {
            self.tree.push(*l);
        }
        InsertCircuit {
            pool_depth: POOL_DEPTH,
            old_root,
            new_root: self.tree.root(),
            k: start / BATCH_LEAVES,
            leaves: padded,
            real,
            path: self.tree.path(start)[BATCH_HEIGHT..].to_vec(),
            zero: self.tree.zero(BATCH_HEIGHT),
        }
    }

    /// Inserts pending batches until note n is committed.
    pub fn commit_note(&mut self, n: &Note) -> Vec<InsertCircuit> {
        let mut v = Vec::new();
        while !self.committed(n) {
            v.push(self.insert_batch());
        }
        v
    }

    /// Deposit(v, u) with u = H_own(addr, rho) for a fresh rho.  The queue holds pairs; a deposit fills the second leaf with 0, which opens to no note.
    pub fn deposit<R: RngCore>(&mut self, v: u64, nsk: Fr, rng: &mut R) -> Note {
        let rho = Fr::rand(rng);
        let pos = self.queue_pair(commit(v, h(Tag::Addr, &[nsk]), rho), Fr::zero());
        Note { v, nsk, rho, pos }
    }

    pub fn nullifier(n: &Note) -> Fr {
        h(Tag::Nf, &[n.nsk, n.rho, Fr::from(n.pos as u64)])
    }

    /// The witness and statement of a withdrawal of note n.
    pub fn withdraw(&mut self, n: &Note, rcpt: Fr, fee: u64, rel: Fr) -> WithdrawCircuit {
        assert!(self.committed(n), "the note's batch is not inserted");
        let nf = Self::nullifier(n);
        assert!(self.spent.insert(nf));
        WithdrawCircuit {
            pool_depth: POOL_DEPTH,
            prt: self.tree.root(),
            nf,
            v: Fr::from(n.v),
            rcpt,
            fee: Fr::from(fee),
            rel,
            nsk: n.nsk,
            rho: n.rho,
            pos: n.pos,
            path: self.tree.path(n.pos),
        }
    }
}

#[derive(Clone)]
pub struct Member {
    pub idv: Fr,
    pub nsk: Fr,
}

impl Member {
    pub fn c(&self) -> Fr {
        h(Tag::Id, &[self.idv])
    }
    pub fn addr(&self) -> Fr {
        h(Tag::Addr, &[self.nsk])
    }
}

pub enum Op {
    /// The payer pays a, split according to the shares.
    Expense { a: u64, s: Vec<u64> },
    /// The payer repays a to slot j.
    Repay { j: usize, a: u64 },
}

/// A group as its members and the contract see it.
#[derive(Clone)]
pub struct Group {
    pub tier: usize,
    pub gk: Fr,
    pub members: Vec<Member>,
    pub tree: Tree,
    pub mroot_s: Fr,
    pub kc: Fr,
    pub gid: Fr,
    pub t: u64,
    pub h_c: Fr,
    pub c: Vec<Fr>,
    /// Plaintext balances, for checking the protocol against the ideal bookkeeping.
    pub b: Vec<i128>,
    /// Set after block h_end.
    pub settling: bool,
    /// The commitment to the signing keys and the challenge period of an off-chain group; both 0 for a group of Section 4.
    pub ks: Fr,
    pub dch: u64,
    pub h_end: u64,
}

/// gid = keccak(kc, mrootS, N, hEnd, ks, Delta) mod r, as InitGroup computes it.
pub fn gid_of(kc: Fr, mroot_s: Fr, tier: usize, h_end: u64, ks: Fr, dch: u64) -> Fr {
    keccak_fr(&[kc, mroot_s, Fr::from(tier as u64), Fr::from(h_end), ks, Fr::from(dch)])
}

impl Group {
    /// Group formation with n members, padded to tier N.  The slots follow the members in the order given.
    pub fn form<R: RngCore>(n: usize, tier: usize, h_end: u64, rng: &mut R) -> Self {
        assert!(1 <= n && n <= tier && tier.is_power_of_two());
        let gk = Fr::rand(rng);
        let members: Vec<Member> = (0..n).map(|_| Member { idv: Fr::rand(rng), nsk: Fr::rand(rng) }).collect();
        let mut tree = Tree::new(tier.trailing_zeros() as usize);
        for l in 0..tier {
            let leaf = if l < n {
                h(Tag::Leaf, &[Fr::from(l as u64 + 1), members[l].c(), members[l].addr()])
            } else {
                Fr::rand(rng)
            };
            tree.push(leaf);
        }
        let mroot_s = h(Tag::Root, &[tree.root(), Fr::from(n as u64)]);
        let kc = h(Tag::Key, &[gk]);
        let gid = gid_of(kc, mroot_s, tier, h_end, Fr::zero(), 0);
        Group {
            tier,
            gk,
            members,
            tree,
            mroot_s,
            kc,
            gid,
            t: 0,
            h_c: Fr::zero(),
            c: vec![Fr::zero(); tier + 4],
            b: vec![0; tier],
            settling: false,
            ks: Fr::zero(),
            dch: 0,
            h_end,
        }
    }

    pub fn n(&self) -> usize {
        self.members.len()
    }

    /// Decrypts the current balances, as a member does.
    pub fn balances(&self) -> Vec<i128> {
        if self.t == 0 {
            return vec![0; self.tier];
        }
        dec(self.gk, &self.c, self.tier).into_iter().map(i_fr).collect()
    }

    /// Prepares the update of payer slot k (1-based) paying from note `input`, and applies it to the group and the pool as the contract would on acceptance.  Returns the circuit, the payee note, the change note and the memo ciphertext.
    pub fn update<R: RngCore>(
        &mut self,
        pool: &mut Pool,
        k: usize,
        op: Op,
        input: &Note,
        fee: u64,
        rel: Fr,
        memo: [Fr; MEMO_LEN],
        rng: &mut R,
    ) -> (UpdateCircuit, Note, Note, Vec<Fr>) {
        assert!(pool.committed(input), "the input note's batch is not inserted");
        let n_tier = self.tier;
        let n = self.n();
        let b = self.balances();
        let (mu, a, j, s) = match op {
            Op::Expense { a, s } => {
                let mut v = s.clone();
                v.resize(n_tier, 0);
                (false, a, k, v)
            }
            Op::Repay { j, a } => {
                let mut v = vec![0; n_tier];
                v[j - 1] = a;
                (true, a, j, v)
            }
        };
        let mut b_new = b.clone();
        b_new[k - 1] += a as i128;
        for l in 0..n_tier {
            b_new[l] -= s[l] as i128;
        }
        // The new ciphertext of the balances and the tags, and the memo under the same nonce.
        let nu = Fr::rand(rng);
        let mut x: Vec<Fr> = b_new.iter().map(|v| fr_i(*v)).collect();
        x.extend_from_slice(&[Fr::from(k as u64), Fr::from(a), if mu { Fr::from(j as u64) } else { Fr::zero() }]);
        let c_new = enc(self.gk, &x, nu);
        let ks = keystream(self.gk, nu, n_tier + 3 + MEMO_LEN);
        let z: Vec<Fr> = (0..MEMO_LEN).map(|i| memo[i] + ks[n_tier + 3 + i]).collect();
        let hz = keccak_fr(&z);
        let h_cn = h(Tag::St, &c_new);
        // Pool.
        let t_out = if mu { a } else { 0 };
        assert!(input.v >= t_out + fee);
        let v_chg = input.v - t_out - fee;
        let nf = Pool::nullifier(input);
        let rho_out = h(Tag::Rho, &[self.gk, nf]);
        let addr_out = if mu { self.members[j - 1].addr() } else { Fr::rand(rng) };
        let cm_out = commit(t_out, addr_out, rho_out);
        let me = &self.members[k - 1];
        let nsk_chg = me.nsk;
        let rho_chg = Fr::rand(rng);
        let cm_chg = commit(v_chg, h(Tag::Addr, &[nsk_chg]), rho_chg);
        let statement = UpdateStatement {
            gid: self.gid,
            t: Fr::from(self.t),
            sigma: Fr::from(self.settling as u64),
            kc: self.kc,
            mroot_s: self.mroot_s,
            h_c: self.h_c,
            h_cn,
            c_new: c_new.clone(),
            hz,
            prt: pool.tree.root(),
            nf,
            cm_out,
            cm_chg,
            fee: Fr::from(fee),
            rel,
        };
        let witness = UpdateWitness {
            gk: self.gk,
            n,
            mroot: self.tree.root(),
            k,
            idv: me.idv,
            addr_k: me.addr(),
            path_k: self.tree.path(k - 1),
            j,
            c_j: self.members[j - 1].c(),
            addr_j: self.members[j - 1].addr(),
            path_j: self.tree.path(j - 1),
            mu,
            a: Fr::from(a),
            s: s.iter().map(|v| Fr::from(*v)).collect(),
            c_old: self.c.clone(),
            v: Fr::from(input.v),
            nsk: input.nsk,
            rho: input.rho,
            pos: input.pos,
            path_in: pool.tree.path(input.pos),
            v_chg: Fr::from(v_chg),
            addr_chg: h(Tag::Addr, &[nsk_chg]),
            rho_chg,
            addr_out,
        };
        // The contract accepts: nullifier, digest, sequence number, and the pair of new notes appended to the queue.
        assert!(pool.spent.insert(nf));
        let pos_out = pool.queue_pair(cm_out, cm_chg);
        let pos_chg = pos_out + 1;
        self.t += 1;
        self.h_c = h_cn;
        self.c = c_new;
        self.b = b_new;
        let out = Note { v: t_out, nsk: if mu { self.members[j - 1].nsk } else { Fr::zero() }, rho: rho_out, pos: pos_out };
        let chg = Note { v: v_chg, nsk: nsk_chg, rho: rho_chg, pos: pos_chg };
        (UpdateCircuit { tier: n_tier, pool_depth: POOL_DEPTH, x: statement, w: witness }, out, chg, z)
    }

    pub fn close(&self) -> CloseCircuit {
        CloseCircuit { tier: self.tier, kc: self.kc, h_c: self.h_c, gk: self.gk, c: self.c.clone() }
    }
}
