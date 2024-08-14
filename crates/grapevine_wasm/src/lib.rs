// use grapevine_common::{Fr, Params};
// // use ff::PrimeField;
// // use grapevine_circuits::{start_input, utils::build_step_inputs, z0_secondary};
// // use grapevine_common::{
// //     console_log, utils::random_fr, wasm::init_panic_hook, Fq, Fr, NovaProof, Params, G1, G2,
// // };
// use js_sys::{Array, Number, Uint8Array};
// // use nova_scotia::{
// //     circom::wasm::load_r1cs, continue_recursive_circuit, create_recursive_circuit, FileLocation,
// // };
// // use num::{BigInt, Num};
// // use serde_json::Value;
// // use std::collections::HashMap;
// use grapevine_circuits::{inputs::{GrapevineArtifacts, GrapevineInputs}, nova::{degree_proof, identity_proof}, utils::{compress_proof, decompress_proof}};
// use nova_scotia::{circom::{circuit::R1CS, reader::load_r1cs}, FileLocation};
// use utils::{bigint_to_fr, fr_to_bigint};
use wasm_bindgen::prelude::*;

// #[cfg(target_family = "wasm")]
// use grapevine_circuits::StringArray;

// pub use wasm_bindgen_rayon::init_thread_pool;
// // pub mod types;
// pub mod types;
// pub mod utils;

// /**
//  * Returns the artifacts used by the Grapevine circuit
//  * 
//  * @param params_string - JSON string of the public parameters
//  * @param r1cs_url - URL of the r1cs file
//  * @param wasm_url - URL of the wasm file
//  * @returns the downloaded and parsed GrapevineArtifacts
//  */
// async fn get_artifacts(params_string: String, r1cs_url: String, wasm_url: String) -> GrapevineArtifacts {
//     // parse public parameters
//     let params: Params = serde_json::from_str(&params_string);
//     // retrieve r1cs file from url
//     let r1cs: R1CS<Fr> = load_r1cs(&FileLocation::URL(r1cs_url)).await;
//     // load wasm file
//     let wasm_location = FileLocation::URL(wasm_url);
//     // return artifacts
//     GrapevineArtifacts { params, r1cs, wasm_location }
// }

// /**
//  * Creates a new IVC Proof representing identity (degree 0)
//  *
//  * @param params_string - JSON string of the public parameters
//  * @param r1cs_url - URL of the r1cs file
//  * @param wasm_url - URL of the wasm file
//  * @param prover_key - JSON string of the prover key
//  * @returns JSON string of the proof
//  */
// #[wasm_bindgen]
// pub async fn identity_proof_wasm(
//     params_string: String,
//     r1cs_url: String,
//     wasm_url: String,
//     prover_key: String,
// ) -> String {
//     console_error_panic_hook::set_once();
//     // create artifacts
//     let artifacts = get_artifacts(params_string, r1cs_url, wasm_url).await;
//     // create inputs from prover key
//     let inputs = GrapevineInputs::from_prover_key(prover_key);
//     // create proof
//     // todo: handle error here
//     let proof = identity_proof(&artifacts, inputs).unwrap();
//     // compress proof and return
//     compress_proof(&proof)
// }

// /**
//  * Creates a degree proof from an existing proof
//  * 
//  * @param params_string - JSON string of the public parameters
//  * @param r1cs_url - URL of the r1cs file
//  * @param wasm_url - URL of the wasm file
//  * @param proof - gzip compressed proof
//  */
// #[wasm_bindgen]
// pub async fn degree_proof_wasm(
//     params_string: String,
//     r1cs_url: String,
//     wasm_url: String,
//     proof: String,
//     prover_key: String,
//     relation_pubkey: String,
//     relation_nullifier: String,
//     scope_address: String,
//     auth_signature: String,
//     previous_inputs: StringArray
// ) -> String {
//     console_error_panic_hook::set_once();
//     // create artifacts
//     let artifacts = get_artifacts(params_string, r1cs_url, wasm_url).await;
//     // decompress proof
//     let proof = decompress_proof(proof);
//     // build inputs
//     let inputs = GrapevineInputs::degree_step(
//         prover_key,
//         relation_pubkey,
//         relation_nullifier,
//         scope_address,
//         auth_signature
//     );
//     // parse previous inputs
//     // let previous_inputs: Vec<Fr> = previous_inputs.iter()
// }

#[wasm_bindgen]
pub fn test() {
    // console_log!("Hello from Rust!");
    let x = 0;
}