#!/bin/bash

cd crates/grapevine_wasm
wasm-pack build --target web
cd -
rm -rf grapevine.js/wasm
mv crates/grapevine_wasm/pkg grapevine.js/wasm