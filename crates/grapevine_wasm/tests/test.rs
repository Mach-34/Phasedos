use grapevine_common::Params;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;
use reqwest::{Client, header::CONTENT_TYPE};
use flate2::read::GzDecoder;
use std::io::Read;
use grapevine_common::account::GrapevineAccount;
// use grapevine_wasm::{identity_proof, degree_proof, verify_grapevine_proof};

// // ugh can't change the name cuz it breaks stuff but adding another is +$5/mo
// pub const BUCKET_URL: &str = "https://bjj-ecdsa-nova.us-southeast-1.linodeobjects.com/grapevine/v1";
// pub const PARAMS_CHUNKS: usize = 10;
// /**
//  * Retrieves gzipped params from a url and unzips it
//  *
//  * @param url - the url to retrieve the params from
//  * @returns - the JSON string of the params
//  */
// #[wasm_bindgen]
// pub async fn retrieve_chunked_params(url: String) -> String {
//     // retrieve the chunked params and assemble
//     let mut artifact_gz = Vec::<u8>::new();
//     let client = Client::new();
//     for i in 0..PARAMS_CHUNKS {
//         let artifact_url = format!("{}/params_{}.gz", url, i);
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

// #[wasm_bindgen_test]
// async fn test_degree_8() {
//     wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_worker);
//     // artifacts
//     let r1cs_url = format!("{}/grapevine.r1cs", BUCKET_URL);
//     let wasm_url = format!("{}/grapevine.wasm", BUCKET_URL);
//     let params_str = retrieve_chunked_params(BUCKET_URL.to_string()).await;

//     // create accounts
//     let num_accounts = 8;
//     let mut accounts = Vec::<GrapevineAccount>::new();
//     for i in 0..num_accounts {
//         let account = GrapevineAccount::new(format!("user_{}", i));
//         accounts.push(account);
//     }
//     // create an identity proof for account 0
//     let prover_key = hex::encode(accounts[0].private_key_raw());
//     // create identity proof
//     let identity_proof = identity_proof(params_str.clone(), r1cs_url.clone(), wasm_url.clone(), prover_key).await;
// }

// #[ignore]
// #[wasm_bindgen_test]
// async fn test_get_params() {
//     wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
//     let params_str = retrieve_chunked_params(BUCKET_URL.to_string()).await;
//     let params = serde_json::from_str::<Params>(&params_str).unwrap();
// }

#[wasm_bindgen_test]
pub fn test_signing() {
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_worker);
    let account = GrapevineAccount::new("User1".into());
    let key = hex::encode(account.private_key_raw());
    grapevine_wasm::identity_step_helper(key);
}