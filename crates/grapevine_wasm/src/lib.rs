use grapevine_common::Params;
// use ff::PrimeField;
// use grapevine_circuits::{start_input, utils::build_step_inputs, z0_secondary};
// use grapevine_common::{
//     console_log, utils::random_fr, wasm::init_panic_hook, Fq, Fr, NovaProof, Params, G1, G2,
// };
use js_sys::{Array, Number, Uint8Array};
// use nova_scotia::{
//     circom::wasm::load_r1cs, continue_recursive_circuit, create_recursive_circuit, FileLocation,
// };
// use num::{BigInt, Num};
// use serde_json::Value;
// use std::collections::HashMap;
use grapevine_circuits::inputs::{GrapevineArtifacts, GrapevineInputs};
use nova_scotia::{circom::reader::load_r1cs, FileLocation};
use utils::{bigint_to_fr, fr_to_bigint};
use wasm_bindgen::prelude::*;

pub use wasm_bindgen_rayon::init_thread_pool;
// pub mod types;
pub mod types;
pub mod utils;

async fn get_artifacts(params_string: String, r1cs_url: String, wasm_url: String) -> GrapevineArtifacts {
    // parse public parameters
    let params: Params = serde_json::from_str(&params_string);
    // retrieve r1cs file from url
    let r1cs = load_r1cs(&FileLocation::URL(r1cs_url)).await;
    // load wasm file
    let wasm = load_wasm(wasm_url).await;
    (params, r1cs, wasm)
}

/**
 * Creates a new IVC Proof representing identity (degree 0)
 *
 * @param params_string - JSON string of the public parameters
 * @param r1cs_url - URL of the r1cs file
 * @param wasm_url - URL of the wasm file
 * @param prover_key - JSON string of the prover key
 * @returns JSON string of the proof
 */
#[wasm_bindgen]
pub async fn identity_proof(
    params_string: String,
    r1cs_url: String,
    wasm_url: String,
    prover_key: String,
) -> String {
    console_error_panic_hook::set_once();
    // create inputs from prover key
    let inputs = GrapevineInputs::from_prover_key(prover_key);
    // create artifacts

}
