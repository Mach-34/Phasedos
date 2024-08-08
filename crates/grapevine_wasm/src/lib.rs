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

extern crate console_error_panic_hook;

#[macro_export]
macro_rules! console_log {
    // Note that this is using the `log` function imported above during
    // `bare_bones`
    ($($t:tt)*) => ($crate::wasm::log(&format_args!($($t)*).to_string()))
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

/**
 * Creates a new IVC Proof representing identity (degree 0)
 * 
 * 
 */
#[wasm_bindgen]
pub fn identity_proof(
    params_string: String,
    r1cs_url: String,
    wasm_url: String
    
) -> String {
    console_error_panic_hook::set_once();
}