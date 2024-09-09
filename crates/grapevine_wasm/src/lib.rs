use babyjubjub_rs::{Point, PrivateKey, Signature};
use ff::PrimeField;
use grapevine_circuits::{
    inputs::{GrapevineArtifacts, GrapevineInputs},
    utils::{compress_proof, decompress_proof},
    Z0_PRIMARY, Z0_SECONDARY,
};
use grapevine_common::{
    compat::{ff_ce_from_le_bytes, ff_ce_to_le_bytes}, errors::GrapevineError, http::requests::{CreateUserRequest, DegreeProofRequest, EmitNullifierRequest, NewRelationshipRequest}, Fr, Params, G1, G2
};
use js_sys::{Array, BigInt as JsBigInt, JsString, Number, Uint8Array};
use nova_scotia::{
    circom::{circuit::R1CS, reader::load_r1cs},
    continue_recursive_circuit, create_recursive_circuit, FileLocation,
};
use num::Num;
use num_bigint::{BigInt, Sign};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, str::FromStr};
use wasm_bindgen::prelude::*;

pub mod types;
// pub mod utils;
pub use wasm_bindgen_rayon::init_thread_pool;
pub const PROOF_OUTPUT_SIZE: usize = 12;

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
pub struct GrapevineWasmArtifacts {
    params: String,
    r1cs_url: String,
    wasm_url: String,
}

#[wasm_bindgen]
impl GrapevineWasmArtifacts {
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
async fn get_artifacts(artifact_locations: &GrapevineWasmArtifacts) -> GrapevineArtifacts {
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

/**
 * Converts a stringified bigint to bn254 Fr
 * @notice assumes little endian order
 *
 * @param val - the bigint to parse
 * @return - the field element
 */
pub fn bigint_to_fr(val: String) -> Result<Fr, GrapevineError> {
    // if the string contains 0x, remove it
    let val = if val.starts_with("0x") {
        val[2..].to_string()
    } else {
        val
    };
    // attempt to parse the string
    let mut bytes = match BigInt::from_str_radix(&val, 16) {
        Ok(bigint) => bigint.to_bytes_be().1,
        Err(e) => return Err(GrapevineError::SerdeError(e.to_string())),
    };
    // pad bytes to end if necessary (LE)
    if bytes.len() < 32 {
        let mut padded = vec![0; 32 - bytes.len()];
        bytes.append(&mut padded);
    }
    let bytes: [u8; 32] = match bytes.try_into() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(GrapevineError::SerdeError(String::from(
                "Invalid bigint length",
            )))
        }
    };

    // convert to field element
    let fr = Fr::from_repr(bytes);
    match &fr.is_some().unwrap_u8() {
        1 => Ok(fr.unwrap()),
        _ => Err(GrapevineError::SerdeError(String::from(
            "Could not parse into bn254 field element",
        ))),
    }
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
        let mut output = outputs[i as usize].to_bytes();
        serialized.set(i, JsValue::from_str(&format!("0x{}", hex::encode(output))));
    }
    serialized
}

/**
 * Given an array of hex strings, returns the proof ouuy
 */
pub fn destringify_proof_outputs(outputs: Array) -> Result<Vec<Fr>, GrapevineError> {
    if outputs.length() != PROOF_OUTPUT_SIZE as u32 {
        return Err(GrapevineError::SerdeError(format!(
            "Invalid proof output length: {}",
            outputs.length()
        )));
    };
    let mut proof_outputs = Vec::new();
    for i in 0..outputs.length() {
        let output = outputs.get(i).as_string().unwrap();
        proof_outputs.push(bigint_to_fr(output)?);
    }
    Ok(proof_outputs)
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
    artifact_locations: &GrapevineWasmArtifacts,
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

#[wasm_bindgen]
pub async fn degree_proof(
    artifact_locations: &GrapevineWasmArtifacts,
    input_map: String,
    chaff_map: String,
    proof_string: String,
    previous_output: Array,
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
    // parse previous inputs
    console_log!(verbose, "Parsing previous outputs");
    let previous_output = destringify_proof_outputs(previous_output).unwrap();
    // decompress proof
    let proof_compressed = serde_json::from_str::<Vec<u8>>(&proof_string).unwrap();
    let mut proof = decompress_proof(&proof_compressed[..]);
    // create the degree proof
    console_log!(verbose, "Creating proof");
    continue_recursive_circuit(
        &mut proof,
        previous_output.clone(),
        artifacts.wasm_location.clone(),
        artifacts.r1cs.clone(),
        private_inputs,
        Z0_PRIMARY.clone(),
        &artifacts.params,
    )
    .await;
    // compress proof and return
    console_log!(verbose, "Compressing proof with gzip");
    let compressed = compress_proof(&proof);
    // stringify proof and return
    console_log!(verbose, "Stringifying proof");
    serde_json::to_string(&compressed).unwrap()
}

/**
 * Verify the correct execution of an IVC proof of the grapevine circuit
 *
 * @param proof - the proof to verify
 * @param public_params - the public params to use to verify the proof
 * @param iterations - the degree of separation proven (iterations should equal 2*degree + 2)
 * @return - the output of the proof if verified
 */
#[wasm_bindgen]
pub async fn verify_grapevine_proof(
    params_string: String,
    proof: String,
    degree: Number,
    verbose: bool,
) -> Array {
    console_error_panic_hook::set_once();
    // parse public parameters
    console_log!(verbose, "Parsing public parameters");
    let params: Params = serde_json::from_str(&params_string).unwrap();
    // decompress proof
    console_log!(verbose, "Decompressing proof");
    let proof_compressed = serde_json::from_str::<Vec<u8>>(&proof).unwrap();
    let proof = decompress_proof(&proof_compressed[..]);
    // convert degree to num steps in the circuit
    let iterations = degree.as_f64().unwrap() as usize * 2 + 2;
    // verify the proof
    console_log!(verbose, "Verifying proof");
    let outputs = proof
        .verify(&params, iterations, &Z0_PRIMARY, &Z0_SECONDARY)
        .unwrap();
    // return stringified outputs
    console_log!(verbose, "Stringifying outputs");
    stringify_proof_outputs(outputs.0)
}

#[wasm_bindgen]
pub async fn bincode_create_user_request(
    username: String,
    pubkey_string: String,
    proof_string: String,
) -> Uint8Array {
    console_error_panic_hook::set_once();
    // parse pubkey
    let pubkey: [u8; 32] = hex::decode(pubkey_string).unwrap().try_into().unwrap();
    // destringify proof (should already be compressed)
    let proof: Vec<u8> = serde_json::from_str::<Vec<u8>>(&proof_string).unwrap();
    // build CreateUserRequest
    let request = CreateUserRequest {
        username,
        pubkey,
        proof,
    };
    // bincode the request
    let serialized = bincode::serialize(&request).unwrap();
    // copy into Uint8Array
    let array = Uint8Array::new_with_length(serialized.len() as u32);
    array.copy_from(&serialized[..]);
    // return
    array
}

#[wasm_bindgen]
pub async fn bincode_degree_proof_request(
    proof_string: String,
    previous: String,
    degree: Number
) -> Uint8Array {
    console_error_panic_hook::set_once();
    // destringify proof (should already be compressed)
    let proof: Vec<u8> = serde_json::from_str::<Vec<u8>>(&proof_string).unwrap();
    // build DegreeProofRequest
    let request = DegreeProofRequest {
        proof,
        previous,
        degree: degree.as_f64().unwrap() as u8,
    };
    // bincode the request
    let serialized = bincode::serialize(&request).unwrap();
    // copy into Uint8Array
    let array = Uint8Array::new_with_length(serialized.len() as u32);
    array.copy_from(&serialized[..]);
    // return
    array
}

#[wasm_bindgen]
pub async fn bincode_new_relationship_request(
    to: String,
    ephemeral_key_string: String,
    signature_ciphertext_string: String,
    nullifier_ciphertext_string: String,
    nullifier_secret_ciphertext_string: String,
) -> Uint8Array {
    console_error_panic_hook::set_once();
    // parse ephemeral key
    let ephemeral_key: [u8; 32] = hex::decode(ephemeral_key_string).unwrap().try_into().unwrap();
    // parse ciphertexts
    let signature_ciphertext: [u8; 80] = hex::decode(signature_ciphertext_string).unwrap().try_into().unwrap();
    let nullifier_ciphertext: [u8; 48] = hex::decode(nullifier_ciphertext_string).unwrap().try_into().unwrap();
    let nullifier_secret_ciphertext: [u8; 48] = hex::decode(nullifier_secret_ciphertext_string).unwrap().try_into().unwrap();
    // build NewRelationshipRequest
    let request = NewRelationshipRequest {
        to,
        ephemeral_key,
        signature_ciphertext,
        nullifier_ciphertext,
        nullifier_secret_ciphertext,
    };
    // bincode the request
    let serialized = bincode::serialize(&request).unwrap();
    // copy into Uint8Array
    let array = Uint8Array::new_with_length(serialized.len() as u32);
    array.copy_from(&serialized[..]);
    // return
    array
}

#[wasm_bindgen]
pub async fn bincode_emit_nullifier_request(
    nullifier_secret_string: String,
    recipient: String,
) -> Uint8Array {
    console_error_panic_hook::set_once();
    // parse nullifier secret
    let nullifier_secret: [u8; 32] = hex::decode(nullifier_secret_string).unwrap().try_into().unwrap();
    // build EmitNullifierRequest
    let request = EmitNullifierRequest {
        nullifier_secret,
        recipient,
    };
    // bincode the request
    let serialized = bincode::serialize(&request).unwrap();
    // copy into Uint8Array
    let array = Uint8Array::new_with_length(serialized.len() as u32);
    array.copy_from(&serialized[..]);
    // return
    array
}