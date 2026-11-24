# Sourced by the scripts: paths, the tools, and the Anvil key 0.
root=$(cd "$(dirname "$0")/.." && pwd)
nices=$root/nices
results=$root/results
mkdir -p "$results"
export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
key=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
