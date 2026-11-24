#!/bin/sh
# The Rust tests of the protocol, the off-chain groups and the rejected updates and posts, and the Foundry test of the Poseidon contract.
set -eu
. "$(dirname "$0")/env.sh"
cd "$nices" && cargo test --release
cd "$nices/contracts" && forge test
