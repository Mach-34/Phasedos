use babyjubjub_rs::Fr as Fr_ce;
use ff::PrimeField;
use grapevine_common::{compat::ff_ce_from_le_bytes, errors::GrapevineError, Fr};
use num::{BigInt, Num};
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use crate::StringArray;
use js_sys::Array;
use grapevine_circuits::inputs::PROOF_OUTPUT_SIZE;
use wasm_bindgen::prelude::*;
use flate2::read::GzDecoder;
use std::io::Read;

pub const PARAMS_CHUNKS: usize = 10;
pub const PROOF_OUTPUT_SIZE: usize = 12;


/**
 * Checks the validity of an auth secret
 * @notice auth secrets must be parsable as a bn254 field element
 *
 * @param auth_secret - the stringified hex of the field element
 * @return - Ok if no violations or error otherwise
 */
pub fn validate_auth_secret(auth_secret: &String) -> Result<(), GrapevineError> {
    // check if the auth secret is a valid field element
    match bigint_to_fr(auth_secret.clone()) {
        Ok(_) => Ok(()),
        Err(e) => Err(GrapevineError::SerdeError(format!(
            "Invalid auth secret: {}",
            e.to_string()
        ))),
    }
}

/**
 * Converts a stringified bigint to bn254 Fr
 * @notice assumes little endian order
 *
 * @param val - the bigint to parse
 * @return - the field element
 */
pub fn bigint_to_fr_ce(val: String) -> Result<Fr_ce, GrapevineError> {
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
    Ok(ff_ce_from_le_bytes(bytes))
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
 * Converts a bn254 Fr to a stringified bigint in little endian
 *
 * @param val - the field element to convert
 * @return - the stringified bigint in hex
 */
pub fn fr_to_bigint(val: Fr) -> String {
    format!("0x{}", hex::encode(val.to_bytes()))
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
        serialized.set(i, JsValue::from_str(&fr_to_bigint(outputs[i as usize])));
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