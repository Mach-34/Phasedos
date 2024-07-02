#!/bin/bash

# Used if testing needs to run
# `node artifacts/grapevine_js/generate_witness.js artifacts/grapevine_js/grapevine.wasm inputs.json ./witness.wtns
# in `Grapevine/crates/grapevine_circuits/circom`
# (make sure to make inputs.json first)
# cleaned up by compile.sh


CIRCOM_DIR=./crates/grapevine_circuits/circom

## Install circomlib dependencies
cd $CIRCOM_DIR
yarn
cd -

## Ensure the existence of the artifacts directory
if [ ! -d "$CIRCOM_DIR/artifacts" ]; then
  mkdir $CIRCOM_DIR/artifacts
fi

## Compile the circuit
circom $CIRCOM_DIR/grapevine.circom --r1cs --wasm --prime bn128 \
  --output $CIRCOM_DIR/artifacts 