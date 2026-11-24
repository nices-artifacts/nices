//! Generates the Solidity side from the Rust side: the Poseidon library, the Groth16 verifiers of every relation, a Poseidon test vector, and a Foundry script that replays a scenario of deposits, groups, updates, a withdrawal, a close and the posts of off-chain groups with real proofs.
//!
//! Usage: export <contracts dir>.  Writes src/PoseidonT3.sol, src/Verifiers.sol, test/Poseidon.t.sol, script/Scenario.s.sol and script/labels.txt.

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_snark::SNARK;
use nices::close::CloseCircuit;
use nices::insert::InsertCircuit;
use nices::hash::{enc, h};
use nices::native::{Group, Note, Op, Pool};
use nices::offchain::OffchainGroup;
use nices::post::PostCircuit;
use nices::params::{poseidon, Tag, MEMO_LEN, POOL_DEPTH, TIERS};
use nices::update::UpdateCircuit;
use nices::withdraw::WithdrawCircuit;
use rand::{rngs::StdRng, SeedableRng};
use std::fmt::Write as _;
use std::fs;

const HEND: u64 = 1_000_000_000;
const MEMBERS: usize = 8;
/// The challenge period of the off-chain groups, in blocks.
const DCH: u64 = 100;
/// Anvil accounts 1 and 2: the relayer and the recipient of the withdrawal.
const RELAYER: &str = "70997970C51812dc3A010C7d01b50e0d17dc79C8";
const RECIPIENT: &str = "3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";

fn d<F: PrimeField>(x: F) -> String {
    x.into_bigint().to_string()
}

fn hex32(x: Fr) -> String {
    x.into_bigint().to_bytes_be().iter().map(|b| format!("{b:02x}")).collect()
}

fn addr(hex: &str) -> Fr {
    let bytes: Vec<u8> = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
    Fr::from_be_bytes_mod_order(&bytes)
}

fn g2(p: &G2Affine) -> [String; 4] {
    [d(p.x.c1), d(p.x.c0), d(p.y.c1), d(p.y.c0)]
}

fn proof_words(p: &Proof<Bn254>) -> String {
    let w: Vec<String> = [d(p.a.x), d(p.a.y)]
        .into_iter()
        .chain(g2(&p.b))
        .chain([d(p.c.x), d(p.c.y)])
        .collect();
    format!("[uint256({}), {}]", w[0], w[1..].join(", "))
}

type M3 = [[Fr; 3]; 3];

fn mat_mul(a: &M3, b: &M3) -> M3 {
    let mut c = [[Fr::zero(); 3]; 3];
    for i in 0..3 {
        for j in 0..3 {
            for k in 0..3 {
                c[i][j] += a[i][k] * b[k][j];
            }
        }
    }
    c
}

/// The optimized form of the permutation: round constants of the partial rounds moved to element 0, and each partial-round matrix factored into a sparse one, the rest pushed back into the last full round before the partial rounds.
struct OptPoseidon {
    c: Vec<[Fr; 3]>,
    m: M3,
    m_pre: M3,
    /// Per partial round: (a, w1, w2, v1, v2) with S = [[a, w1, w2], [v1, 1, 0], [v2, 0, 1]].
    sparse: Vec<[Fr; 5]>,
    half: usize,
    partial: usize,
}

fn opt_poseidon() -> OptPoseidon {
    let p = poseidon();
    assert_eq!(p.rate + p.capacity, 3);
    let m: M3 = [0, 1, 2].map(|i| [0, 1, 2].map(|j| p.mds[i][j]));
    let mut c: Vec<[Fr; 3]> = p.ark.iter().map(|r| [r[0], r[1], r[2]]).collect();
    let half = p.full_rounds / 2;
    let partial = p.partial_rounds;
    for r in half..half + partial {
        let rest = [Fr::zero(), c[r][1], c[r][2]];
        for i in 0..3 {
            c[r + 1][i] += m[i][1] * rest[1] + m[i][2] * rest[2];
        }
        c[r][1] = Fr::zero();
        c[r][2] = Fr::zero();
    }
    let mut sparse = vec![[Fr::zero(); 5]; partial];
    let mut acc = m;
    for r in (0..partial).rev() {
        let (pp, q, rr, ss) = (acc[1][1], acc[1][2], acc[2][1], acc[2][2]);
        let det_inv = ark_ff::Field::inverse(&(pp * ss - q * rr)).unwrap();
        let (r0, r1) = (acc[0][1], acc[0][2]);
        let w1 = (r0 * ss - r1 * rr) * det_inv;
        let w2 = (r1 * pp - r0 * q) * det_inv;
        sparse[r] = [acc[0][0], w1, w2, acc[1][0], acc[2][0]];
        let pmat: M3 = [[Fr::from(1u64), Fr::zero(), Fr::zero()], [Fr::zero(), pp, q], [Fr::zero(), rr, ss]];
        acc = mat_mul(&pmat, &m);
    }
    OptPoseidon { c, m, m_pre: acc, sparse, half, partial }
}

fn pow5(x: Fr) -> Fr {
    let x2 = x * x;
    x2 * x2 * x
}

impl OptPoseidon {
    fn permute(&self, mut s: [Fr; 3]) -> [Fr; 3] {
        let full = |s: &mut [Fr; 3], c: &[Fr; 3], m: &M3| {
            let x = [0, 1, 2].map(|i| pow5(s[i] + c[i]));
            *s = [0, 1, 2].map(|i| m[i][0] * x[0] + m[i][1] * x[1] + m[i][2] * x[2]);
        };
        for r in 0..self.half {
            let m = if r + 1 == self.half { &self.m_pre } else { &self.m };
            full(&mut s, &self.c[r], m);
        }
        for (k, sp) in self.sparse.iter().enumerate() {
            let x0 = pow5(s[0] + self.c[self.half + k][0]);
            s = [sp[0] * x0 + sp[1] * s[1] + sp[2] * s[2], sp[3] * x0 + s[1], sp[4] * x0 + s[2]];
        }
        for r in self.half + self.partial..self.c.len() {
            full(&mut s, &self.c[r], &self.m);
        }
        s
    }
}

fn poseidon_sol() -> String {
    let o = opt_poseidon();
    // The optimized permutation agrees with arkworks.
    let mut rng = StdRng::seed_from_u64(9);
    for tag in [Tag::Node, Tag::Cm] {
        let (a, b) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
        assert_eq!(o.permute([tag.fr(), a, b])[1], h(tag, &[a, b]));
    }
    let mut y = String::new();
    let full = |y: &mut String, c: &[Fr; 3], m: &M3| {
        for i in 0..3 {
            writeln!(y, "            s{i} := addmod(s{i}, {}, F)", d(c[i])).unwrap();
            writeln!(y, "            t := mulmod(s{i}, s{i}, F)\n            t := mulmod(t, t, F)\n            s{i} := mulmod(s{i}, t, F)").unwrap();
        }
        let row = |i: usize| format!("addmod(addmod(mulmod(s0, {}, F), mulmod(s1, {}, F), F), mulmod(s2, {}, F), F)", d(m[i][0]), d(m[i][1]), d(m[i][2]));
        writeln!(y, "            n0 := {}\n            n1 := {}\n            s2 := {}\n            s0 := n0\n            s1 := n1", row(0), row(1), row(2)).unwrap();
    };
    for r in 0..o.half {
        full(&mut y, &o.c[r], if r + 1 == o.half { &o.m_pre } else { &o.m });
    }
    for (k, sp) in o.sparse.iter().enumerate() {
        let c0 = o.c[o.half + k][0];
        writeln!(y, "            s0 := addmod(s0, {}, F)\n            t := mulmod(s0, s0, F)\n            t := mulmod(t, t, F)\n            s0 := mulmod(s0, t, F)", d(c0)).unwrap();
        writeln!(y, "            n0 := addmod(addmod(mulmod(s0, {}, F), mulmod(s1, {}, F), F), mulmod(s2, {}, F), F)", d(sp[0]), d(sp[1]), d(sp[2])).unwrap();
        writeln!(y, "            s1 := addmod(mulmod(s0, {}, F), s1, F)\n            s2 := addmod(mulmod(s0, {}, F), s2, F)\n            s0 := n0", d(sp[3]), d(sp[4])).unwrap();
    }
    for r in o.half + o.partial..o.c.len() {
        full(&mut y, &o.c[r], &o.m);
    }
    let mut z = vec![Fr::zero()];
    for i in 0..POOL_DEPTH {
        z.push(h(Tag::Node, &[z[i], z[i]]));
    }
    let zs: String = z.iter().map(|x| hex32(*x)).collect();
    format!(
        r#"// SPDX-License-Identifier: GPL-3.0-or-later
// Generated by `cargo run --release --bin export`; do not edit.
pragma solidity ^0.8.24;

/// Poseidon over BN254 as in arkworks: width 3, rate 2, capacity 1, x^5, 8 full and 57 partial rounds, unrolled, with the round constants of the partial rounds moved to the first element and sparse partial-round matrices.  H_tag(a, b) permutes (tag, a, b) and returns the second entry.
contract PoseidonT3 {{
    function hash(uint256 tag, uint256 a, uint256 b) external pure returns (uint256 out) {{
        assembly {{
            let F := 21888242871839275222246405745257275088548364400416034343698204186575808495617
            let s0 := tag
            let s1 := a
            let s2 := b
            let t := 0
            let n0 := 0
            let n1 := 0
{y}            out := s1
        }}
    }}
}}

/// The root of an empty subtree of each height 0 to {depth}.
library PoseidonZeros {{
    bytes internal constant ZEROS = hex"{zs}";

    function zero(bytes memory zs, uint256 i) internal pure returns (uint256 z) {{
        assembly {{
            z := mload(add(zs, add(0x20, mul(i, 0x20))))
        }}
    }}
}}
"#,
        depth = POOL_DEPTH,
    )
}

fn verifier_sol(name: &str, vk: &VerifyingKey<Bn254>) -> String {
    let k = vk.gamma_abc_g1.len() - 1;
    let ic = |p: &G1Affine| (d(p.x), d(p.y));
    let (x0, y0) = ic(&vk.gamma_abc_g1[0]);
    let mut acc = String::new();
    for (i, p) in vk.gamma_abc_g1[1..].iter().enumerate() {
        let (x, y) = ic(p);
        writeln!(acc, "        (x, y) = _mulAdd(x, y, {x}, {y}, input[{i}]);").unwrap();
    }
    let set = |off: usize, w: [String; 4]| -> String {
        w.iter().enumerate().map(|(i, v)| format!("        p[{}] = {v};\n", off + i)).collect()
    };
    format!(
        r#"
/// Groth16 verifier of {name}, {k} public inputs.
contract {name} {{
    function verify(uint256[] calldata input, uint256[8] calldata proof) external view returns (bool) {{
        require(input.length == {k}, "inputs");
        uint256 x = {x0};
        uint256 y = {y0};
{acc}        uint256[24] memory p;
        p[0] = proof[0];
        p[1] = proof[1] % Q == 0 ? 0 : Q - (proof[1] % Q);
        p[2] = proof[2];
        p[3] = proof[3];
        p[4] = proof[4];
        p[5] = proof[5];
        p[6] = {ax};
        p[7] = {ay};
{beta}        p[12] = x;
        p[13] = y;
{gamma}        p[18] = proof[6];
        p[19] = proof[7];
{delta}        return _pairing(p);
    }}
}}
"#,
        ax = d(vk.alpha_g1.x),
        ay = d(vk.alpha_g1.y),
        beta = set(8, g2(&vk.beta_g2)),
        gamma = set(14, g2(&vk.gamma_g2)),
        delta = set(20, g2(&vk.delta_g2)),
    )
}

const VERIFIER_HEADER: &str = r#"// SPDX-License-Identifier: GPL-3.0-or-later
// Generated by `cargo run --release --bin export`; do not edit.
pragma solidity ^0.8.24;

uint256 constant Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
uint256 constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

/// (x, y) + s * (px, py) with the EIP-196 precompiles; s must be a field element.
function _mulAdd(uint256 x, uint256 y, uint256 px, uint256 py, uint256 s) view returns (uint256 rx, uint256 ry) {
    require(s < R, "input");
    assembly {
        let m := mload(0x40)
        mstore(m, px)
        mstore(add(m, 0x20), py)
        mstore(add(m, 0x40), s)
        if iszero(staticcall(gas(), 7, m, 0x60, m, 0x40)) { revert(0, 0) }
        mstore(add(m, 0x40), x)
        mstore(add(m, 0x60), y)
        if iszero(staticcall(gas(), 6, m, 0x80, m, 0x40)) { revert(0, 0) }
        rx := mload(m)
        ry := mload(add(m, 0x20))
    }
}

/// e(-A, B) e(alpha, beta) e(vk_x, gamma) e(C, delta) = 1 with the EIP-197 precompile.
function _pairing(uint256[24] memory p) view returns (bool ok) {
    uint256[1] memory out;
    bool success;
    assembly {
        success := staticcall(gas(), 8, p, 768, out, 0x20)
    }
    ok = success && out[0] == 1;
}
"#;

enum Action {
    Deploy(String),
    Deposit { v: u64, u: Fr },
    Init { kc: Fr, mroot_s: Fr, tier: usize, ks: Fr, dch: u64 },
    Post { gid: Fr, c: PostCircuit },
    Update { label: String, c: UpdateCircuit, z: Vec<Fr> },
    Withdraw(WithdrawCircuit),
    Insert(InsertCircuit),
    Close { gid: Fr, c: CloseCircuit },
}

fn setup<C: ConstraintSynthesizer<Fr> + Clone>(c: &C, rng: &mut StdRng) -> (ProvingKey<Bn254>, VerifyingKey<Bn254>) {
    Groth16::<Bn254>::circuit_specific_setup(c.clone(), rng).unwrap()
}

fn prove<C: ConstraintSynthesizer<Fr> + Clone>(pk: &ProvingKey<Bn254>, vk: &VerifyingKey<Bn254>, c: &C, inputs: &[Fr], rng: &mut StdRng) -> Proof<Bn254> {
    let p = Groth16::<Bn254>::prove(pk, c.clone(), rng).unwrap();
    assert!(Groth16::<Bn254>::verify(vk, inputs, &p).unwrap());
    p
}

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| "contracts".into());
    let mut rng = StdRng::seed_from_u64(2026);
    fs::create_dir_all(format!("{dir}/test")).unwrap();
    fs::write(format!("{dir}/src/PoseidonT3.sol"), poseidon_sol()).unwrap();
    let (a, b) = (Fr::from(1u64), Fr::from(2u64));
    fs::write(
        format!("{dir}/test/Poseidon.t.sol"),
        format!(
            r#"// SPDX-License-Identifier: GPL-3.0-or-later
// Generated by `cargo run --release --bin export`; do not edit.
pragma solidity ^0.8.24;

import {{Test, console}} from "forge-std/Test.sol";
import {{PoseidonT3, PoseidonZeros}} from "../src/PoseidonT3.sol";

contract PoseidonTest is Test {{
    function test_matches_arkworks() public {{
        PoseidonT3 p = new PoseidonT3();
        assertEq(p.hash({node}, 1, 2), {h12});
        assertEq(PoseidonZeros.zero(PoseidonZeros.ZEROS, 1), {z1});
        uint256 x = 1;
        uint256 g = gasleft();
        for (uint256 i; i < 20; i++) {{
            x = p.hash({node}, x, i);
        }}
        console.log("gas per hash", (g - gasleft()) / 20);
    }}
}}
"#,
            node = Tag::Node as u64,
            h12 = d(h(Tag::Node, &[a, b])),
            z1 = d(h(Tag::Node, &[Fr::zero(), Fr::zero()])),
        ),
    )
    .unwrap();

    let rel = addr(RELAYER);
    let memo = [Fr::from(0x4e49434553u64); MEMO_LEN];
    let mut pool = Pool::new();
    let mut actions: Vec<Action> = Vec::new();
    actions.push(Action::Deploy("PoseidonT3".into()));
    for t in TIERS {
        actions.push(Action::Deploy(format!("VerifierUpdate{t}")));
    }
    for t in TIERS {
        actions.push(Action::Deploy(format!("VerifierClose{t}")));
    }
    for t in TIERS {
        actions.push(Action::Deploy(format!("VerifierPost{t}")));
    }
    actions.push(Action::Deploy("VerifierWithdraw".into()));
    actions.push(Action::Deploy("VerifierInsert".into()));
    actions.push(Action::Deploy("NICES".into()));

    // Every member of every group deposits: 32 pairs, one full batch, inserted before the first update.
    let mut groups: Vec<(Group, Vec<Note>)> = Vec::new();
    for tier in TIERS {
        let n = MEMBERS.min(tier);
        let g = Group::form(n, tier, HEND, &mut rng);
        let mut notes: Vec<Note> = Vec::new();
        for l in 0..n {
            let note = pool.deposit(1_000_000, g.members[l].nsk, &mut rng);
            actions.push(Action::Deposit { v: note.v, u: h(Tag::Own, &[note.addr(), note.rho]) });
            notes.push(note);
        }
        groups.push((g, notes));
    }
    while pool.pending() {
        actions.push(Action::Insert(pool.insert_batch()));
    }
    for (mut g, mut notes) in groups {
        let tier = g.tier;
        let n = g.n();
        actions.push(Action::Init { kc: g.kc, mroot_s: g.mroot_s, tier, ks: Fr::zero(), dch: 0 });
        let mut op = |g: &mut Group, pool: &mut Pool, notes: &mut Vec<Note>, label: String, k: usize, o: Op, rng: &mut StdRng| -> Note {
            let input = notes[k - 1].clone();
            for c in pool.commit_note(&input) {
                actions.push(Action::Insert(c));
            }
            let (c, out, chg, z) = g.update(pool, k, o, &input, 1, rel, memo, rng);
            notes[k - 1] = chg;
            actions.push(Action::Update { label, c, z });
            out
        };
        let s = vec![100u64; n];
        op(&mut g, &mut pool, &mut notes, format!("update N={tier} expense t=0"), 1, Op::Expense { a: 100 * n as u64, s }, &mut rng);
        let out = op(&mut g, &mut pool, &mut notes, format!("update N={tier} repayment"), 2, Op::Repay { j: 1, a: 100 }, &mut rng);
        let s = vec![10u64; n];
        op(&mut g, &mut pool, &mut notes, format!("update N={tier} expense t>0"), 3, Op::Expense { a: 10 * n as u64, s }, &mut rng);
        if tier == TIERS[0] {
            // Settle greedily: the largest debtor pays the largest creditor.
            loop {
                let b = g.balances();
                let (dk, dv) = b.iter().enumerate().min_by_key(|(_, v)| **v).map(|(i, v)| (i, *v)).unwrap();
                if dv == 0 {
                    break;
                }
                let (ck, cv) = b.iter().enumerate().max_by_key(|(_, v)| **v).map(|(i, v)| (i, *v)).unwrap();
                let amt = (-dv).min(cv) as u64;
                op(&mut g, &mut pool, &mut notes, format!("update N={tier} settlement"), dk + 1, Op::Repay { j: ck + 1, a: amt }, &mut rng);
            }
            actions.push(Action::Close { gid: g.gid, c: g.close() });
            for c in pool.commit_note(&out) {
                actions.push(Action::Insert(c));
            }
            actions.push(Action::Withdraw(pool.withdraw(&out, addr(RECIPIENT), 1, rel)));
        }
    }

    // Off-chain groups: per tier, a full group records one expense per member off-chain and posts a state and then the final state; for the smallest tier, the debtors then repay on-chain and a member closes the group.
    for tier in TIERS {
        let mut og = OffchainGroup::form(tier, tier, HEND, DCH, &mut rng);
        actions.push(Action::Init { kc: og.g.kc, mroot_s: og.g.mroot_s, tier, ks: og.g.ks, dch: DCH });
        for k in 1..=tier {
            og.expense(k, 10 * k as u64 * tier as u64, &vec![10 * k as u64; tier], &mut rng);
            if k == tier / 2 {
                actions.push(Action::Post { gid: og.g.gid, c: og.post(false, &mut rng) });
            }
        }
        actions.push(Action::Post { gid: og.g.gid, c: og.post(true, &mut rng) });
        if tier == TIERS[0] {
            let mut g = og.g.clone();
            g.settling = true;
            let mut notes: Vec<Note> = Vec::new();
            for l in 0..tier {
                let note = pool.deposit(1_000_000, g.members[l].nsk, &mut rng);
                actions.push(Action::Deposit { v: note.v, u: h(Tag::Own, &[note.addr(), note.rho]) });
                notes.push(note);
            }
            loop {
                let b = g.balances();
                let (dk, dv) = b.iter().enumerate().min_by_key(|(_, v)| **v).map(|(i, v)| (i, *v)).unwrap();
                if dv == 0 {
                    break;
                }
                let (ck, cv) = b.iter().enumerate().max_by_key(|(_, v)| **v).map(|(i, v)| (i, *v)).unwrap();
                let input = notes[dk].clone();
                for c in pool.commit_note(&input) {
                    actions.push(Action::Insert(c));
                }
                let (c, _, chg, z) = g.update(&mut pool, dk + 1, Op::Repay { j: ck + 1, a: (-dv).min(cv) as u64 }, &input, 1, rel, memo, &mut rng);
                notes[dk] = chg;
                actions.push(Action::Update { label: format!("update N={tier} off-chain settlement"), c, z });
            }
            actions.push(Action::Close { gid: g.gid, c: g.close() });
        }
    }

    // Keys: one setup per relation, from an instance of the scenario or, for close, a group with zero balances.
    let mut keys_upd = Vec::new();
    let mut keys_cl = Vec::new();
    let mut keys_post = Vec::new();
    for tier in TIERS {
        let c = actions
            .iter()
            .find_map(|a| match a {
                Action::Post { c, .. } if c.tier == tier => Some(c.clone()),
                _ => None,
            })
            .unwrap();
        keys_post.push(setup(&c, &mut rng));
        let c = actions
            .iter()
            .find_map(|a| match a {
                Action::Update { c, .. } if c.tier == tier => Some(c.clone()),
                _ => None,
            })
            .unwrap();
        keys_upd.push(setup(&c, &mut rng));
        let gk = Fr::rand(&mut rng);
        let ct = enc(gk, &vec![Fr::zero(); tier + 3], Fr::rand(&mut rng));
        let cl = CloseCircuit { tier, kc: h(Tag::Key, &[gk]), h_c: h(Tag::St, &ct), gk, c: ct };
        keys_cl.push(setup(&cl, &mut rng));
    }
    let wd = actions.iter().find_map(|a| if let Action::Withdraw(c) = a { Some(c.clone()) } else { None }).unwrap();
    let key_wd = setup(&wd, &mut rng);
    let ins = actions.iter().find_map(|a| if let Action::Insert(c) = a { Some(c.clone()) } else { None }).unwrap();
    let key_ins = setup(&ins, &mut rng);
    // The proving keys, for the settlement experiment, which proves against the deployed verifiers.
    fs::create_dir_all(format!("{dir}/keys")).unwrap();
    let save = |name: String, pk: &ProvingKey<Bn254>| {
        let mut f = std::io::BufWriter::new(fs::File::create(format!("{dir}/keys/{name}.pk")).unwrap());
        ark_serialize::CanonicalSerialize::serialize_uncompressed(pk, &mut f).unwrap();
    };
    for (i, t) in TIERS.iter().enumerate() {
        save(format!("update{t}"), &keys_upd[i].0);
        save(format!("close{t}"), &keys_cl[i].0);
        save(format!("post{t}"), &keys_post[i].0);
    }
    save("withdraw".into(), &key_wd.0);
    save("insert".into(), &key_ins.0);

    let mut sol = VERIFIER_HEADER.to_string();
    for (i, t) in TIERS.iter().enumerate() {
        sol += &verifier_sol(&format!("VerifierUpdate{t}"), &keys_upd[i].1);
    }
    for (i, t) in TIERS.iter().enumerate() {
        sol += &verifier_sol(&format!("VerifierClose{t}"), &keys_cl[i].1);
    }
    for (i, t) in TIERS.iter().enumerate() {
        sol += &verifier_sol(&format!("VerifierPost{t}"), &keys_post[i].1);
    }
    sol += &verifier_sol("VerifierWithdraw", &key_wd.1);
    sol += &verifier_sol("VerifierInsert", &key_ins.1);
    fs::write(format!("{dir}/src/Verifiers.sol"), sol).unwrap();

    let ti = |t: usize| TIERS.iter().position(|x| *x == t).unwrap();
    let mut labels = String::new();
    let mut calls = String::new();
    let mut fns = String::new();
    for (i, a) in actions.iter().enumerate() {
        let body = match a {
            Action::Deploy(name) => {
                writeln!(labels, "deploy {name}").unwrap();
                continue;
            }
            Action::Deposit { v, u } => {
                writeln!(labels, "deposit").unwrap();
                format!("        nices.deposit{{value: {v}}}({v}, {});\n", d(*u))
            }
            Action::Init { kc, mroot_s, tier, ks, dch } => {
                writeln!(labels, "initGroup N={tier}{}", if ks.is_zero() { "" } else { " off-chain" }).unwrap();
                format!("        nices.initGroup({}, {}, {tier}, {HEND}, {}, {dch});\n", d(*kc), d(*mroot_s), d(*ks))
            }
            Action::Post { gid, c } => {
                let f = !c.x.f.is_zero();
                writeln!(labels, "post N={} {}", c.tier, if f { "final" } else { "state" }).unwrap();
                let (pk, vk) = &keys_post[ti(c.tier)];
                let p = prove(pk, vk, c, &c.x.inputs(), &mut rng);
                let mut s = format!("        uint256[] memory c = new uint256[]({});\n", c.x.c.len());
                for (k, v) in c.x.c.iter().enumerate() {
                    writeln!(s, "        c[{k}] = {};", d(*v)).unwrap();
                }
                writeln!(s, "        nices.post({}, {}, {}, c, {}, {});", d(*gid), d(c.x.t), d(c.x.f), d(c.x.h_c), proof_words(&p)).unwrap();
                s
            }
            Action::Update { label, c, z } => {
                writeln!(labels, "{label}").unwrap();
                let (pk, vk) = &keys_upd[ti(c.tier)];
                let p = prove(pk, vk, c, &c.x.inputs(), &mut rng);
                let x = &c.x;
                let mut s = String::from("        NICES.UpdateArgs memory a;\n");
                writeln!(s, "        a.gid = {};\n        a.t = {};", d(x.gid), d(x.t)).unwrap();
                writeln!(s, "        a.cNew = new uint256[]({});", x.c_new.len()).unwrap();
                for (k, v) in x.c_new.iter().enumerate() {
                    writeln!(s, "        a.cNew[{k}] = {};", d(*v)).unwrap();
                }
                let zs: Vec<String> = z.iter().map(|v| d(*v)).collect();
                writeln!(s, "        a.hCn = {};\n        a.z = [uint256({}), {}];", d(x.h_cn), zs[0], zs[1..].join(", ")).unwrap();
                writeln!(s, "        a.prt = {};\n        a.nf = {};\n        a.cmOut = {};\n        a.cmChg = {};", d(x.prt), d(x.nf), d(x.cm_out), d(x.cm_chg)).unwrap();
                writeln!(s, "        a.fee = {};\n        a.rel = {};\n        a.proof = {};\n        nices.update(a);", d(x.fee), d(x.rel), proof_words(&p)).unwrap();
                s
            }
            Action::Withdraw(c) => {
                writeln!(labels, "withdraw").unwrap();
                let p = prove(&key_wd.0, &key_wd.1, c, &c.inputs(), &mut rng);
                format!(
                    "        nices.withdraw({}, {}, {}, {}, {}, {}, {});\n",
                    d(c.prt), d(c.nf), d(c.v), d(c.rcpt), d(c.fee), d(c.rel), proof_words(&p)
                )
            }
            Action::Insert(c) => {
                writeln!(labels, "insertBatch {} leaves", c.real).unwrap();
                let p = prove(&key_ins.0, &key_ins.1, c, &c.inputs(), &mut rng);
                let mut s = format!("        uint256[] memory l = new uint256[]({});\n", c.real);
                for (k, v) in c.leaves[..c.real].iter().enumerate() {
                    writeln!(s, "        l[{k}] = {};", d(*v)).unwrap();
                }
                writeln!(s, "        nices.insertBatch(l, {}, {});", d(c.new_root), proof_words(&p)).unwrap();
                s
            }
            Action::Close { gid, c } => {
                writeln!(labels, "close N={}", c.tier).unwrap();
                let (pk, vk) = &keys_cl[ti(c.tier)];
                let p = prove(pk, vk, c, &c.inputs(), &mut rng);
                format!("        nices.close({}, {});\n", d(*gid), proof_words(&p))
            }
        };
        writeln!(calls, "        a{i}();").unwrap();
        write!(fns, "\n    function a{i}() internal {{\n{body}    }}\n").unwrap();
    }
    let n = TIERS.len();
    let mut deploy = String::new();
    writeln!(deploy, "        PoseidonT3 pos = new PoseidonT3();").unwrap();
    writeln!(deploy, "        uint256[] memory tiers = new uint256[]({n});\n        IVerifier[] memory upd = new IVerifier[]({n});\n        IVerifier[] memory cl = new IVerifier[]({n});\n        IVerifier[] memory pst = new IVerifier[]({n});").unwrap();
    for (i, t) in TIERS.iter().enumerate() {
        writeln!(deploy, "        tiers[{i}] = {t};\n        upd[{i}] = IVerifier(address(new VerifierUpdate{t}()));").unwrap();
    }
    for (i, t) in TIERS.iter().enumerate() {
        writeln!(deploy, "        cl[{i}] = IVerifier(address(new VerifierClose{t}()));").unwrap();
    }
    for (i, t) in TIERS.iter().enumerate() {
        writeln!(deploy, "        pst[{i}] = IVerifier(address(new VerifierPost{t}()));").unwrap();
    }
    writeln!(deploy, "        IVerifier wd = IVerifier(address(new VerifierWithdraw()));\n        IVerifier ins = IVerifier(address(new VerifierInsert()));\n        nices = new NICES(pos, tiers, upd, cl, pst, wd, ins);").unwrap();
    let script = format!(
        r#"// SPDX-License-Identifier: GPL-3.0-or-later
// Generated by `cargo run --release --bin export`; do not edit.
pragma solidity ^0.8.24;

import {{Script}} from "forge-std/Script.sol";
import {{NICES, IVerifier}} from "../src/NICES.sol";
import {{PoseidonT3}} from "../src/PoseidonT3.sol";
import "../src/Verifiers.sol";

/// Replays the scenario of `export`; script/labels.txt names its transactions in order.
contract Scenario is Script {{
    NICES nices;

    function run() external {{
        vm.startBroadcast();
{deploy}{calls}        vm.stopBroadcast();
    }}
{fns}}}
"#
    );
    fs::write(format!("{dir}/script/Scenario.s.sol"), script).unwrap();
    let deploy_script = format!(
        r#"// SPDX-License-Identifier: GPL-3.0-or-later
// Generated by `cargo run --release --bin export`; do not edit.
pragma solidity ^0.8.24;

import {{Script, console}} from "forge-std/Script.sol";
import {{NICES, IVerifier}} from "../src/NICES.sol";
import {{PoseidonT3}} from "../src/PoseidonT3.sol";
import "../src/Verifiers.sol";

/// Deploys the contracts with the verifiers of keys/, for the settlement experiment.
contract Deploy is Script {{
    function run() external {{
        vm.startBroadcast();
{deploy}        vm.stopBroadcast();
        console.log("NICES", address(nices));
    }}
    NICES nices;
}}
"#
    );
    fs::write(format!("{dir}/script/Deploy.s.sol"), deploy_script).unwrap();
    fs::write(format!("{dir}/script/labels.txt"), labels).unwrap();
    eprintln!("{} transactions", actions.len());
}
