#!/usr/bin/env bash
# Builds the heavy_init guest and its Wizer-preinitialized twin (DESIGN.md §4.3).
#
# Requires: rustup target add wasm32-wasip1
#           cargo install wizer --all-features
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
guest="$here/examples/heavy_init"
dist="$guest/dist"

mkdir -p "$dist"

cargo build --release --target wasm32-wasip1 --manifest-path "$guest/Cargo.toml"
cp "$guest/target/wasm32-wasip1/release/heavy_init.wasm" "$dist/heavy_init.wasm"

# --init-func: the guest names its initializer for the WASI reactor convention,
#   not Wizer's default of `wizer.initialize`.
# --allow-wasi: Wizer instantiates the module to run the initializer, so every
#   import must be satisfiable at build time. The guest imports only WASI.
#
# Wizer drops the init export afterwards (its default). That is what lets the
# runtime tell the two artifacts apart without a flag of its own: the raw module
# still exports `_initialize` and gets it called, the wizened one does not.
wizer --allow-wasi --init-func _initialize \
  -o "$dist/initialized.wasm" "$dist/heavy_init.wasm"

ls -l "$dist"
