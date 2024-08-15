use grapevine_common::{compat::ff_ce_to_le_bytes, crypto::pubkey_to_address, Fr, Params, G1, G2};
// // use ff::PrimeField;
// // use grapevine_circuits::{start_input, utils::build_step_inputs, z0_secondary};
// // use grapevine_common::{
// //     console_log, utils::random_fr, wasm::init_panic_hook, Fq, Fr, NovaProof, Params, G1, G2,
// // };
// use js_sys::{Array, Number, Uint8Array};
// // use nova_scotia::{
// //     circom::wasm::load_r1cs, continue_recursive_circuit, create_recursive_circuit, FileLocation,
// // };
// use num::{BigInt, Num};
// // use serde_json::Value;
// // use std::collections::HashMap;
use grapevine_circuits::{Z0_PRIMARY, Z0_SECONDARY, inputs::{GrapevineArtifacts, GrapevineInputs}, utils::{compress_proof, decompress_proof}};
// use nova_scotia::{circom::{circuit::R1CS, reader::load_r1cs}, continue_recursive_circuit, create_recursive_circuit, FileLocation};
// use utils::{bigint_to_fr, destringify_proof_outputs, fr_to_bigint, stringify_proof_outputs};
use wasm_bindgen::prelude::*;
use babyjubjub_rs::PrivateKey;
use num_bigint::{BigInt, Sign};
// pub use wasm_bindgen_rayon::init_thread_pool;
// // pub mod types;
// pub mod types;
// pub mod utils;


#[wasm_bindgen]
extern "C" {
    // Use `js_namespace` here to bind `console.log(..)` instead of just
    // `log(..)`
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);

    // The `console.log` is quite polymorphic, so we can bind it with multiple
    // signatures. Note that we need to use `js_name` to ensure we always call
    // `log` in JS.
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn log_u32(a: u32);

    // Multiple arguments too!
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn log_many(a: &str, b: &str);

    pub type Performance;

    pub static performance: Performance;

    #[wasm_bindgen(method)]
    pub fn now(this: &Performance) -> f64;

    #[wasm_bindgen(js_class = Array, typescript_type = "Array<string>")]
    pub type StringArray;
}

#[macro_export]
macro_rules! console_log {
    // Note that this is using the `log` function imported above during
    // `bare_bones`
    ($($t:tt)*) => ($crate::log(&format_args!($($t)*).to_string()))
}

// pub fn identity_step_helper(prover_key: String) -> GrapevineInputs {
//     // convert prover key from string to 
//     console_log!("Converting prover key: {:?}", &prover_key);
//     let prover_key_bytes = hex::decode(prover_key).unwrap();
//     console_log!("Importing prover key: {:?}", &prover_key_bytes);
//     let prover_key = PrivateKey::import(prover_key_bytes).unwrap();


//     // try sign
//     console_log!("Attempting to sign");
//     let message = BigInt::from_bytes_le(Sign::Plus, &[0x00]);
//     let scope_signature = prover_key.sign(message).unwrap();
//     console_log!("Signed!");

//     // get the pubkey used by the prover
//     console_log!("Getting prover pubkey:");
//     let prover_pubkey = prover_key.public();
//     // get the account address
//     console_log!("Getting prover address");
//     let address = pubkey_to_address(&prover_pubkey);
//     // sign the address
//     console_log!("Creating message to sign");
//     let message = BigInt::from_bytes_le(Sign::Plus, &ff_ce_to_le_bytes(&address));
//     console_log!("Signing message");
//     let scope_signature = prover_key.sign(message).unwrap();
//     GrapevineInputs {
//         nullifier: None,
//         prover_pubkey,
//         relation_pubkey: None,
//         scope_signature,
//         auth_signature: None,
//     }
// }

pub fn identity_step_helper(prover_key: String) {
    // convert prover key from string to 
    console_log!("Converting prover key: {:?}", &prover_key);
    let prover_key_bytes = hex::decode(prover_key).unwrap();
    console_log!("Importing prover key: {:?}", &prover_key_bytes);
    let prover_key = PrivateKey::import(prover_key_bytes).unwrap();


    // try sign
    console_log!("Attempting to sign");
    let message = BigInt::from_bytes_le(Sign::Plus, &[0x00]);
    let scope_signature = prover_key.sign(message).unwrap();
    console_log!("Signed!");

    // get the pubkey used by the prover
    console_log!("Getting prover pubkey:");
    let prover_pubkey = prover_key.public();
    // get the account address
    console_log!("Getting prover address");
    let address = pubkey_to_address(&prover_pubkey);
    // sign the address
    console_log!("Creating message to sign");
    let message = BigInt::from_bytes_le(Sign::Plus, &ff_ce_to_le_bytes(&address));
    console_log!("Signing message");
    let scope_signature = prover_key.sign(message).unwrap();
    let x = GrapevineInputs {
        nullifier: None,
        prover_pubkey,
        relation_pubkey: None,
        scope_signature,
        auth_signature: None,
    };
}

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
//     let params: Params = serde_json::from_str(&params_string).unwrap();
//     // retrieve r1cs file from url
//     let r1cs: R1CS<Fr> = load_r1cs::<G1, G2>(&FileLocation::URL(r1cs_url)).await;
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
// pub async fn identity_proof(
//     params_string: String,
//     r1cs_url: String,
//     wasm_url: String,
//     prover_key: String,
// ) -> String {
//     console_error_panic_hook::set_once();
//     // create artifacts
//     console_log!("Creating artifacts");
//     let artifacts = get_artifacts(params_string, r1cs_url, wasm_url).await;
//     // create inputs from prover key
//     console_log!("Generating inputs");
//     // let inputs = GrapevineInputs::identity_step(prover_key);
//     let inputs = identity_step_helper(prover_key);
//     console_log!("Formatting inputs for circom");
//     let private_inputs = inputs.fmt_circom();
//     // create the degree proof
//     console_log!("Creating proof");
//     let proof = create_recursive_circuit(
//         artifacts.wasm_location.clone(),
//         artifacts.r1cs.clone(),
//         private_inputs.to_vec(),
//         Z0_PRIMARY.clone(),
//         &artifacts.params,
//     ).await.unwrap();
//     // compress proof and return
//     console_log!("Compressing proof");
//     let compressed = compress_proof(&proof);
//     console_log!("Serializing proof");
//     serde_json::to_string(&compressed).unwrap()
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
// pub async fn degree_proof(
//     params_string: String,
//     r1cs_url: String,
//     wasm_url: String,
//     proof_string: String,
//     prover_key: String,
//     relation_pubkey: String,
//     relation_nullifier: String,
//     scope_address: String,
//     auth_signature: String,
//     previous_output: Array
// ) -> String {
//     console_error_panic_hook::set_once();
//     // create artifacts
//     let artifacts = get_artifacts(params_string, r1cs_url, wasm_url).await;
//     // decompress proof
//     let proof_compressed = serde_json::from_str::<Vec<u8>>(&proof_string).unwrap();
//     let mut proof = decompress_proof(&proof_compressed[..]);
//     // build inputs
//     let inputs = GrapevineInputs::degree_step(
//         prover_key,
//         relation_pubkey,
//         relation_nullifier,
//         scope_address,
//         auth_signature
//     );
//     // parse previous inputs
//     let previous_output = destringify_proof_outputs(previous_output).unwrap();

//     // create the degree proof
//     // get the formatted inputs to the circuit
//     let private_inputs = inputs.fmt_circom();
//     // create the degree proof
//     continue_recursive_circuit(
//         &mut proof,
//         previous_output.clone(),
//         artifacts.wasm_location.clone(),
//         artifacts.r1cs.clone(),
//         private_inputs.to_vec(),
//         Z0_PRIMARY.clone(),
//         &artifacts.params,
//     ).await.unwrap();

//     // compress proof and return
//     let compressed = compress_proof(&proof);
//     serde_json::to_string(&compressed).unwrap()
// }

// /**
//  * Verify the correct execution of an IVC proof of the grapevine circuit
//  *
//  * @param proof - the proof to verify
//  * @param public_params - the public params to use to verify the proof
//  * @param iterations - the degree of separation proven (iterations should equal 2*degree + 2)
//  * @return - the output of the proof if verified
//  */
// #[wasm_bindgen]
// pub async fn verify_grapevine_proof(
//     proof: String,
//     params_string: String,
//     degree: Number
// ) -> Array {
//     // parse public parameters
//     let params: Params = serde_json::from_str(&params_string).unwrap();
//     // decompress proof
//     let proof_compressed = serde_json::from_str::<Vec<u8>>(&proof).unwrap();
//     let proof = decompress_proof(&proof_compressed[..]);
//     // convert degree to num steps in the circuit
//     let iterations = degree.as_f64().unwrap() as usize * 2 + 2;
//     // verify the proof
//     let outputs = proof.verify(&params, iterations, &Z0_PRIMARY, &Z0_SECONDARY).unwrap();
//     // return stringified outputs
//     stringify_proof_outputs(outputs.0)
// }

#[wasm_bindgen]
pub fn test() {
    let x = 0;
}