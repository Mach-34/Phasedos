#!/bin/bash

CIRCOM_DIR=./crates/grapevine_circuits/circom

## Install circomlib dependencies
cd $CIRCOM_DIR
yarn

## remove any testing artifacts
rm inputs.json
rm witness.wtns
cd -

## Ensure the existence of the artifacts directory
if [ ! -d "$CIRCOM_DIR/artifacts" ]; then
  mkdir $CIRCOM_DIR/artifacts
fi

## Compile the circuit
circom $CIRCOM_DIR/grapevine.circom --r1cs --wasm --prime bn128 \
  --output $CIRCOM_DIR/artifacts 

## Remove unnecessary artifacts
mv $CIRCOM_DIR/artifacts/grapevine_js/grapevine.wasm $CIRCOM_DIR/artifacts
rm -rf $CIRCOM_DIR/artifacts/grapevine_js

## Generate the public parameters, including chunks
cargo run --package grapevine_circuits --bin gen_params --release

## Copy the public parameters and the wasm file to the server
STATIC_FS_DIR=./crates/grapevine_server/static
cp $CIRCOM_DIR/artifacts/public_params.json $STATIC_FS_DIR
cp $CIRCOM_DIR/artifacts/grapevine.wasm $STATIC_FS_DIR
cp $CIRCOM_DIR/artifacts/grapevine.r1cs $STATIC_FS_DIR