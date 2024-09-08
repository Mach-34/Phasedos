use std::{collections::HashMap, str::FromStr};

use babyjubjub_rs::{Point, PrivateKey, Signature};
use grapevine_circuits::{
    inputs::{GrapevineArtifacts, GrapevineInputs},
    utils::{compress_proof, decompress_proof},
    Z0_PRIMARY, Z0_SECONDARY,
};
use grapevine_common::{
    compat::{ff_ce_from_le_bytes, ff_ce_to_le_bytes},
    crypto::pubkey_to_address,
    Fr, Params, G1, G2,
};
use js_sys::{BigInt as JsBigInt, JsString, Uint8Array, Array, Number};
use nova_scotia::{
    circom::{circuit::R1CS, reader::load_r1cs},
    continue_recursive_circuit, create_recursive_circuit, FileLocation,
};
use num_bigint::{BigInt, Sign};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use wasm_bindgen::prelude::*;

pub mod types;
// pub mod utils;
pub use wasm_bindgen_rayon::init_thread_pool;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputMapJson {
    pub prover_pubkey: Vec<String>,
    pub relation_pubkey: Vec<String>,
    pub relation_nullifier: String,
    pub auth_signature: Vec<String>,
    pub scope_signature: Vec<String>,
}

impl InputMapJson {
    pub fn to_map(&self) -> HashMap<String, Value> {
        let mut map = HashMap::new();
        map.insert(
            "prover_pubkey".to_string(),
            json!(self.prover_pubkey.clone()),
        );
        map.insert(
            "relation_pubkey".to_string(),
            json!(self.relation_pubkey.clone()),
        );
        map.insert(
            "relation_nullifier".to_string(),
            json!(self.relation_nullifier.clone()),
        );
        map.insert(
            "auth_signature".to_string(),
            json!(self.auth_signature.clone()),
        );
        map.insert(
            "scope_signature".to_string(),
            json!(self.scope_signature.clone()),
        );
        map
    }
}

#[wasm_bindgen]
pub struct WasmArtifacts {
    params: String,
    r1cs_url: String,
    wasm_url: String,
}

#[wasm_bindgen]
impl WasmArtifacts {
    #[wasm_bindgen(constructor)]
    pub fn new(params: String, r1cs_url: String, wasm_url: String) -> Self {
        Self {
            params,
            r1cs_url,
            wasm_url,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn params(&self) -> String {
        self.params.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn r1cs_url(&self) -> String {
        self.r1cs_url.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn wasm_url(&self) -> String {
        self.wasm_url.clone()
    }
}

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
    // Version with verbosity check (verbose flag passed)
    ($verbose:expr, $($t:tt)*) => {
        if $verbose {
            $crate::log(&format_args!($($t)*).to_string())
        }
    };
}

/**
 * Returns the artifacts used by the Grapevine circuit
 *
 * @param params_string - JSON string of the public parameters
 * @param r1cs_url - URL of the r1cs file
 * @param wasm_url - URL of the wasm file
 * @returns the downloaded and parsed GrapevineArtifacts
 */
async fn get_artifacts(artifact_locations: &WasmArtifacts) -> GrapevineArtifacts {
    // parse public parameters
    let params: Params = serde_json::from_str(&artifact_locations.params()).unwrap();
    // retrieve r1cs file from url
    let r1cs: R1CS<Fr> =
        load_r1cs::<G1, G2>(&FileLocation::URL(artifact_locations.r1cs_url())).await;
    // load wasm file
    let wasm_location = FileLocation::URL(artifact_locations.wasm_url());
    // return artifacts
    GrapevineArtifacts {
        params,
        r1cs,
        wasm_location,
    }
}

// test converting bigint to hex string in rust to determine if it can access it all
#[wasm_bindgen]
pub async fn bigint_test(num: JsBigInt) -> String {
    // console_log!("XXXXX: {:?}", num);
    "x".to_string()
}

/**
 * Turns the output of a proof (Vec<Fr>) into an array of hex strings for js
 *
 * @param outputs - the proof outputs as given by novascotia
 * @returns - the array of hex strings
 */
pub fn stringify_proof_outputs(outputs: Vec<Fr>) -> Array {
    let serialized = Array::new_with_length(outputs.len() as u32);
    for i in 0..outputs.len() as u32 {
        let output = outputs[i as usize].to_bytes();
        serialized.set(i, JsValue::from_str(&format!("0x{}", hex::encode(output))));
    }
    serialized
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
    artifact_locations: &WasmArtifacts,
    input_map: String,
    chaff_map: String,
    verbose: bool,
) -> String {
    console_error_panic_hook::set_once();
    // create artifacts
    console_log!(verbose, "Retrieving and parsing artifacts");
    let artifacts = get_artifacts(artifact_locations).await;
    // parse the circuit inputs
    console_log!(verbose, "Parsing inputs");
    let inputs = serde_json::from_str::<InputMapJson>(&input_map).unwrap();
    let chaff = serde_json::from_str::<InputMapJson>(&chaff_map).unwrap();
    let private_inputs = vec![inputs.to_map(), chaff.to_map()];
    // create the proof
    console_log!(verbose, "Creating proof");
    let proof = create_recursive_circuit(
        artifacts.wasm_location.clone(),
        artifacts.r1cs.clone(),
        private_inputs,
        Z0_PRIMARY.clone(),
        &artifacts.params,
    )
    .await
    .unwrap();
    // compress proof and return
    console_log!(verbose, "Compressing proof with gzip");
    let compressed = compress_proof(&proof);
    // stringify proof and return
    console_log!(verbose, "Stringifying proof");
    serde_json::to_string(&compressed).unwrap()
}

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

/**
 * Verify the correct execution of an IVC proof of the grapevine circuit
 *
 * @param proof - the proof to verify
 * @param public_params - the public params to use to verify the proof
 * @param iterations - the degree of separation proven (iterations should equal 2*degree + 2)
 * @return - the output of the proof if verified
 */
#[wasm_bindgen]
pub async fn verify_grapevine_proof(proof: String, params_string: String, degree: Number) -> Array {
    // parse public parameters
    let params: Params = serde_json::from_str(&params_string).unwrap();
    // decompress proof
    let proof_compressed = serde_json::from_str::<Vec<u8>>(&proof).unwrap();
    let proof = decompress_proof(&proof_compressed[..]);
    // convert degree to num steps in the circuit
    let iterations = degree.as_f64().unwrap() as usize * 2 + 2;
    // verify the proof
    let outputs = proof
        .verify(&params, iterations, &Z0_PRIMARY, &Z0_SECONDARY)
        .unwrap();
    // return stringified outputs
    stringify_proof_outputs(outputs.0)
}

#[wasm_bindgen]
pub fn test() {
    let x = 0;
}
