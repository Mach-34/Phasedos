#!/bin/bash

cd crates/grapevine_wasm
wasm-pack build --target web
cd -
rm -rf grapevine.js/grapevine_wasm
mv crates/grapevine_wasm/pkg grapevine.js/grapevine_wasm