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
use utils::{bigint_to_fr, fr_to_bigint};
use wasm_bindgen::prelude::*;

pub use wasm_bindgen_rayon::init_thread_pool;
// pub mod types;
pub mod utils;
pub mod types;




/**
 * Creates a new IVC Proof representing identity (degree 0)
 * 
 * 
 */
#[wasm_bindgen]
pub fn identity_proof(
    params_string: String,
    r1cs_url: String,
    wasm_url: String,
    prover_key: String,
) -> String {
    console_error_panic_hook::set_once();

}