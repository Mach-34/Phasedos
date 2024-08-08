use ff::{FromUniformBytes, PrimeField};
use poseidon_rs::Fr as Fr_ce;
use flate2::read::GzDecoder;
use grapevine_common::{
    compat::ff_ce_from_le_bytes, errors::GrapevineError, utils::convert_phrase_to_fr,
    Fr, MAX_SECRET_CHARS, MAX_USERNAME_CHARS, compat::ff_ce_from_le_bytes
};
use num::{BigInt, Num};
use reqwest::header::CONTENT_TYPE;
use std::io::Read;
use wasm_bindgen::prelude::*;

pub const PARAMS_CHUNKS: usize = 10;

// /**
//  * Retrieves gzipped params from a url and unzips it
//  *
//  * @param url - the url to retrieve the params from
//  * @param chunks - the number of file chunks
//  *   - if < 2 no chunks added
//  *   - if >= 2, append -{chunk #} to the url for each chunk
//  */
// #[wasm_bindgen]
// pub async fn retrieve_chunked_params(url: String) -> String {
//     // retrieve the chunked params and assemble
//     let mut artifact_gz = Vec::<u8>::new();
//     let client = reqwest::Client::new();
//     for i in 0..PARAMS_CHUNKS {
//         let artifact_url = format!("{}params_{}.gz", url, i);
//         let mut chunk = client
//             .get(&artifact_url)
//             .header(CONTENT_TYPE, "application/x-binary")
//             .send()
//             .await
//             .unwrap()
//             .bytes()
//             .await
//             .unwrap()
//             .to_vec();
//         artifact_gz.append(&mut chunk);
//     }
//     // decompress the artifact
//     let mut decoder = GzDecoder::new(&artifact_gz[..]);
//     let mut serialized = String::new();
//     decoder.read_to_string(&mut serialized).unwrap();

//     serialized
// }

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
        Err(e) => Err(GrapevineError::AuthSecret(format!(
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
        Err(e) => return Err(GrapevineError::AuthSecret(e.to_string())),
    };
    // pad bytes to end if necessary (LE)
    if bytes.len() < 32 {
        let mut padded = vec![0; 32 - bytes.len()];
        bytes.append(&mut padded);
    }
    let bytes: [u8; 32] = match bytes.try_into() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(GrapevineError::AuthSecret(String::from(
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
        Err(e) => return Err(GrapevineError::AuthSecret(e.to_string())),
    };
    // pad bytes to end if necessary (LE)
    if bytes.len() < 32 {
        let mut padded = vec![0; 32 - bytes.len()];
        bytes.append(&mut padded);
    }
    let bytes: [u8; 32] = match bytes.try_into() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(GrapevineError::AuthSecret(String::from(
                "Invalid bigint length",
            )))
        }
    };

    // convert to field element
    let fr = Fr::from_repr(bytes);
    match &fr.is_some().unwrap_u8() {
        1 => Ok(fr.unwrap()),
        _ => Err(GrapevineError::AuthSecret(String::from(
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