use grapevine_common::{Fq, Fr, SECRET_FIELD_LENGTH};
use lazy_static::lazy_static;

pub mod nova;
pub mod utils;
pub mod inputs;
mod params_gen;

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

lazy_static! {
    pub(crate) static ref Z0_PRIMARY: Vec<Fr> = vec![Fr::from(0); 12];
    pub(crate) static ref Z0_SECONDARY: Vec<Fq> = vec![Fq::from(0)];
}

pub const ZERO: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
pub const DEFAULT_WC_PATH: &str =
    "crates/grapevine_circuits/circom/artifacts/folded_js/folded.wasm";
pub const DEFAULT_R1CS_PATH: &str = "crates/grapevine_circuits/circom/artifacts/folded.r1cs";
pub const DEFAULT_PUBLIC_PARAMS_PATH: &str =
    "crates/grapevine_circuits/circom/artifacts/public_params.json";

#[cfg(target_family = "wasm")]
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
    ($($t:tt)*) => ($log(&format_args!($($t)*).to_string()))
}
