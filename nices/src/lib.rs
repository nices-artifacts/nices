//! NICES: confidential expense splitting with Poseidon encryption of the balances.
//!
//! The crate implements the relations of the paper, the update, close and post relations of each tier, the withdrawal relation and the batch insertion relation, as arkworks circuits for Groth16 over BN254, together with a native model of a group and of the note pool that produces their statements and witnesses.

pub mod params;
pub mod hash;
pub mod gadgets;
pub mod tree;
pub mod native;
pub mod update;
pub mod withdraw;
pub mod close;
pub mod insert;
pub mod offchain;
pub mod post;
