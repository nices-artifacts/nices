// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

import {PoseidonT3, PoseidonZeros} from "./PoseidonT3.sol";

interface IVerifier {
    function verify(uint256[] calldata input, uint256[8] calldata proof) external view returns (bool);
}

/// The NICES contract of Algorithm 1: all groups and one shielded note pool, settled in ETH.  New notes wait in a queue of batches of at most B pairs, and anyone inserts the oldest batch into the pool tree with a proof of R_ins.
contract NICES {
    uint256 internal constant R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant TMAX = 1 << 32;
    uint256 internal constant DEPTH = 32;
    uint256 internal constant W = 32;
    uint256 internal constant B = 32;
    uint256 internal constant LEAVES = 2 * B;
    uint256 internal constant TAG_CM = 10;

    struct Group {
        uint256 kc;
        uint256 mrootS;
        uint256 hC;
        uint64 tier;
        uint64 hEnd;
        uint64 t;
        bool open;
        bool offchain;
    }

    /// The state of an off-chain group: the commitment to the signing keys, the challenge period, the block of the first post (0 before it), and whether a final state was posted.
    struct Offchain {
        uint256 ks;
        uint64 dch;
        uint64 postStart;
        bool fin;
    }

    /// The arguments of Update: the statement of R_upd^N without the values the contract supplies, the memo ciphertext and the proof.
    struct UpdateArgs {
        uint256 gid;
        uint256 t;
        uint256[] cNew;
        uint256 hCn;
        uint256[4] z;
        uint256 prt;
        uint256 nf;
        uint256 cmOut;
        uint256 cmChg;
        uint256 fee;
        uint256 rel;
        uint256[8] proof;
    }

    mapping(uint256 => Group) public groups;
    mapping(uint256 => IVerifier) public updateVerifier;
    mapping(uint256 => IVerifier) public closeVerifier;
    mapping(uint256 => IVerifier) public postVerifier;
    mapping(uint256 => Offchain) public offchain;
    IVerifier public immutable withdrawVerifier;
    IVerifier public immutable insertVerifier;
    PoseidonT3 public immutable poseidon;

    uint256[W] public roots;
    uint256 public rootIndex;
    mapping(uint256 => bool) public spent;
    /// The Keccak chain over the pairs queued in each batch not yet inserted.
    mapping(uint256 => bytes32) public chains;
    uint64 public openBatch;
    uint64 public openCount;
    uint64 public nextInsert;

    /// Pair `index` of batch `batch`, at leaf positions LEAVES * batch + 2 * index and the next.
    event Queued(uint256 indexed batch, uint256 index, uint256 l, uint256 r);

    constructor(PoseidonT3 pos, uint256[] memory tiers, IVerifier[] memory upd, IVerifier[] memory cl, IVerifier[] memory pst, IVerifier wd, IVerifier ins) {
        for (uint256 i; i < tiers.length; i++) {
            updateVerifier[tiers[i]] = upd[i];
            closeVerifier[tiers[i]] = cl[i];
            postVerifier[tiers[i]] = pst[i];
        }
        withdrawVerifier = wd;
        insertVerifier = ins;
        poseidon = pos;
        roots[0] = PoseidonZeros.zero(PoseidonZeros.ZEROS, DEPTH);
    }

    function isKnownRoot(uint256 root) public view returns (bool) {
        if (root == 0) return false;
        uint256 i = rootIndex;
        for (uint256 k; k < W; k++) {
            if (roots[i] == root) return true;
            i = i == 0 ? W - 1 : i - 1;
        }
        return false;
    }

    /// Appends the pair (l, r) to the open batch, and seals the batch when it holds B pairs.
    function _queuePair(uint256 l, uint256 r) internal {
        uint256 b = openBatch;
        uint256 c = openCount;
        chains[b] = keccak256(abi.encodePacked(chains[b], l, r));
        emit Queued(b, c, l, r);
        if (c + 1 == B) {
            (openBatch, openCount) = (uint64(b + 1), 0);
        } else {
            openCount = uint64(c + 1);
        }
    }

    /// Inserts the oldest pending batch, sealing the open batch if no sealed one waits.  `leaves` are its queued leaves in order; the circuit pads them with zeros to LEAVES.
    function insertBatch(uint256[] calldata leaves, uint256 newRoot, uint256[8] calldata proof) external {
        uint256 b = nextInsert;
        uint256 count = B;
        if (b == openBatch) {
            count = openCount;
            require(count > 0, "empty");
            (openBatch, openCount) = (uint64(b + 1), 0);
        }
        require(leaves.length == 2 * count && (b + 1) * LEAVES <= 1 << DEPTH, "leaves");
        bytes32 chain;
        for (uint256 i; i < leaves.length; i += 2) {
            chain = keccak256(abi.encodePacked(chain, leaves[i], leaves[i + 1]));
        }
        require(chain == chains[b], "chain");
        uint256[] memory x = new uint256[](3 + LEAVES);
        (x[0], x[1], x[2]) = (roots[rootIndex], newRoot, b);
        for (uint256 i; i < leaves.length; i++) {
            x[3 + i] = leaves[i];
        }
        require(insertVerifier.verify(x, proof), "proof");
        delete chains[b];
        uint256 ri = (rootIndex + 1) % W;
        roots[ri] = newRoot;
        rootIndex = ri;
        nextInsert = uint64(b + 1);
    }

    function deposit(uint256 v, uint256 u) external payable {
        require(msg.value == v && v < 1 << 64 && u < R, "deposit");
        _queuePair(poseidon.hash(TAG_CM, v, u), 0);
    }

    /// ks = 0 creates a group of Section 4; ks != 0 an off-chain group with challenge period dch.
    function initGroup(uint256 kc, uint256 mrootS, uint64 tier, uint64 hEnd, uint256 ks, uint64 dch) external returns (uint256 gid) {
        require(address(updateVerifier[tier]) != address(0), "tier");
        gid = uint256(keccak256(abi.encodePacked(kc, mrootS, uint256(tier), uint256(hEnd), ks, uint256(dch)))) % R;
        require(groups[gid].tier == 0, "duplicate");
        bool off = ks != 0;
        if (off) {
            require(dch > 0 && ks < R, "offchain");
            offchain[gid] = Offchain(ks, dch, 0, false);
        }
        groups[gid] = Group(kc, mrootS, 0, tier, hEnd, 0, true, off);
    }

    /// An off-chain group is settled on-chain once its challenge period has ended, a final state is posted, or block hEnd + 2 dch has passed without a post.
    function settled(uint256 gid) public view returns (bool) {
        Group storage g = groups[gid];
        if (!g.offchain) return true;
        Offchain storage o = offchain[gid];
        if (o.fin) return true;
        if (o.postStart == 0) return block.number > g.hEnd + 2 * uint256(o.dch);
        return block.number >= uint256(o.postStart) + o.dch;
    }

    /// Post(gid, t', f, C, hC, proof): places a co-signed state of an off-chain group on-chain.
    function post(uint256 gid, uint256 t, uint256 f, uint256[] calldata c, uint256 hC, uint256[8] calldata proof) external {
        Group storage g = groups[gid];
        Offchain storage o = offchain[gid];
        uint256 n = g.tier;
        require(g.open && g.offchain && !o.fin && t > g.t && f < 2 && c.length == n + 4, "state");
        if (o.postStart == 0) {
            require(block.number <= g.hEnd + 2 * uint256(o.dch), "late");
        } else {
            require(block.number < uint256(o.postStart) + o.dch, "settled");
        }
        uint256[] memory x = new uint256[](n + 10);
        (x[0], x[1], x[2], x[3], x[4], x[5]) = (g.kc, g.mrootS, o.ks, t, f, hC);
        for (uint256 i; i < n + 4; i++) {
            x[6 + i] = c[i];
        }
        require(postVerifier[n].verify(x, proof), "proof");
        g.t = uint64(t);
        g.hC = hC;
        if (o.postStart == 0) o.postStart = uint64(block.number);
        if (f == 1) o.fin = true;
    }

    function update(UpdateArgs calldata a) external {
        Group storage g = groups[a.gid];
        uint256 n = g.tier;
        require(g.open && a.t == g.t && a.t < TMAX, "state");
        bool fin;
        if (g.offchain) {
            require(settled(a.gid), "challenge");
            fin = offchain[a.gid].fin;
        }
        require(a.cNew.length == n + 4 && a.rel < 1 << 160, "args");
        require(isKnownRoot(a.prt) && !spent[a.nf], "note");
        uint256[] memory x = new uint256[](n + 18);
        x[0] = a.gid;
        x[1] = a.t;
        x[2] = block.number > g.hEnd || fin ? 1 : 0;
        x[3] = g.kc;
        x[4] = g.mrootS;
        x[5] = g.hC;
        x[6] = a.hCn;
        for (uint256 i; i < n + 4; i++) {
            x[7 + i] = a.cNew[i];
        }
        uint256 k = n + 11;
        x[k] = uint256(keccak256(abi.encodePacked(a.z))) % R;
        x[k + 1] = a.prt;
        x[k + 2] = a.nf;
        x[k + 3] = a.cmOut;
        x[k + 4] = a.cmChg;
        x[k + 5] = a.fee;
        x[k + 6] = a.rel;
        require(updateVerifier[n].verify(x, a.proof), "proof");
        g.hC = a.hCn;
        g.t = uint64(a.t + 1);
        spent[a.nf] = true;
        _queuePair(a.cmOut, a.cmChg);
        if (a.fee > 0) payable(address(uint160(a.rel))).transfer(a.fee);
    }

    function withdraw(uint256 prt, uint256 nf, uint256 v, uint256 rcpt, uint256 fee, uint256 rel, uint256[8] calldata proof) external {
        require(isKnownRoot(prt) && !spent[nf], "note");
        require(fee <= v && rcpt < 1 << 160 && rel < 1 << 160, "args");
        uint256[] memory x = new uint256[](6);
        (x[0], x[1], x[2], x[3], x[4], x[5]) = (prt, nf, v, rcpt, fee, rel);
        require(withdrawVerifier.verify(x, proof), "proof");
        spent[nf] = true;
        payable(address(uint160(rcpt))).transfer(v - fee);
        if (fee > 0) payable(address(uint160(rel))).transfer(fee);
    }

    function close(uint256 gid, uint256[8] calldata proof) external {
        Group storage g = groups[gid];
        require(g.open && g.t > 0 && settled(gid), "state");
        uint256[] memory x = new uint256[](2);
        (x[0], x[1]) = (g.kc, g.hC);
        require(closeVerifier[g.tier].verify(x, proof), "proof");
        g.open = false;
    }
}
