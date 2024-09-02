#!/bin/bash

cd crates/grapevine_wasm
wasm-pack build --target web
cd -
mv crates/grapevine_wasm/pkg grapevine.js/grapevine_wasm