#!/usr/bin/env bash
# Builds the guests and their Wizer-preinitialized twins.
#
#   examples/heavy_init    — the §4.3 demonstration
#   interpreters/js        — the JavaScript interpreter of §22.1
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

# --- The JavaScript interpreter (§22.1) --------------------------------------
#
# Same recipe, and for a much better reason: an interpreter's boot *is* building
# its realm — every intrinsic, before a line of user code runs. Un-wizened, this
# guest would spend most of a tool call constructing `Object` and `JSON`.
js="$here/interpreters/js"
js_dist="$js/dist"

mkdir -p "$js_dist"

cargo build --release --target wasm32-wasip1 --manifest-path "$js/Cargo.toml"
cp "$js/target/wasm32-wasip1/release/nebula_js.wasm" "$js_dist/nebula_js.wasm"

wizer --allow-wasi --init-func _initialize \
  -o "$js_dist/initialized.wasm" "$js_dist/nebula_js.wasm"

ls -l "$js_dist"
