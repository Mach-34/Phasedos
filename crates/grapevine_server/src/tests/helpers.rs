use crate::{
    catchers::bad_request,
    health,
    mongo::GrapevineDB,
    routes,
    tests::http::{
        http_add_relationship, http_create_user, http_get_available_proofs, http_get_proving_data,
        http_submit_degree_proof,
    },
    utils::{use_public_params, use_r1cs, use_wasm},
};
use babyjubjub_rs::{decompress_point, decompress_signature};
use ff::PrimeField;
use grapevine_circuits::{
    inputs::{GrapevineArtifacts, GrapevineInputs, GrapevineOutputs},
    nova::{degree_proof, verify_grapevine_proof},
    utils::{compress_proof, decompress_proof},
};
use grapevine_common::{
    account::GrapevineAccount,
    auth_secret::AuthSecretEncrypted,
    http::requests::{CreateUserRequest, DegreeProofRequest},
    models::ProvingData,
    Fr, NovaProof,
};
use lazy_static::lazy_static;
use rocket::{
    fs::{relative, FileServer},
    local::asynchronous::Client,
};
use std::sync::Mutex;

lazy_static! {
    static ref USERS: Mutex<Vec<GrapevineAccount>> = Mutex::new(vec![]);
    pub static ref ARTIFACTS: GrapevineArtifacts = GrapevineArtifacts {
        params: use_public_params().unwrap(),
        r1cs: use_r1cs().unwrap(),
        wasm_path: use_wasm().unwrap()
    };
}

pub struct GrapevineTestContext {
    pub client: Client,
}

impl GrapevineTestContext {
    pub async fn init() -> Self {
        let database_name = String::from("grapevine_mocked");
        let mongo = GrapevineDB::init(&database_name, &*crate::MONGODB_URI).await;
        let rocket = rocket::build()
            // add mongodb client to context
            .manage(mongo)
            // mount user routes
            .mount("/user", &**routes::USER_ROUTES)
            // mount proof routes
            .mount("/proof", &**routes::PROOF_ROUTES)
            // mount test routes
            .mount("/", routes![health])
            // mount artifact file server
            .mount("/static", FileServer::from(relative!("static")))
            .register("/", catchers![bad_request]);

        GrapevineTestContext {
            client: Client::tracked(rocket).await.unwrap(),
        }
    }
}

/**
 * Build a grapevine identity proof (degree 0) given a grapevine account
 *
 * @return the grapevine proof
 */
pub fn build_identity_proof(from: &GrapevineAccount) -> NovaProof {
    // get inputs
    let private_key = &from.private_key();
    let identity_inputs = GrapevineInputs::identity_step(private_key);
    grapevine_circuits::nova::identity_proof(&*ARTIFACTS, &identity_inputs).unwrap()
}

/**
 * Handles repeatable process of parsing proving data, decompressing proofs, verifying -> outputs, etc
 *
 * @param user - the account to handle the proving data
 * @param data - the proving data to handle
 * @param degree - the degree of the proof to build
 * @returns - the proof to build from and inputs for the next degree proof
 */
pub fn build_degree_inputs(
    user: &GrapevineAccount,
    proving_data: &ProvingData,
    degree: u8,
) -> (NovaProof, GrapevineInputs, GrapevineOutputs) {
    let mut proof = decompress_proof(&proving_data.proof[..]);
    let res = verify_grapevine_proof(&proof, &*&ARTIFACTS.params, degree as usize)
        .unwrap()
        .0;
    let outputs = GrapevineOutputs::try_from(res).unwrap();
    // decrypt the auth secret
    let auth_secret_encrypted = AuthSecretEncrypted {
        ephemeral_key: proving_data.ephemeral_key,
        signature_ciphertext: proving_data.signature_ciphertext,
        nullifier_ciphertext: proving_data.nullifier_ciphertext,
    };
    let auth_secret = auth_secret_encrypted.decrypt(user.private_key());
    // build the inputs for the degree proof
    let auth_signature = decompress_signature(&auth_secret.signature).unwrap();
    let relation_pubkey = decompress_point(proving_data.relation_pubkey).unwrap();
    let relation_nullifier = Fr::from_repr(auth_secret.nullifier).unwrap();
    let inputs = GrapevineInputs::degree_step(
        &user.private_key(),
        &relation_pubkey,
        &relation_nullifier,
        &outputs.scope,
        &auth_signature,
    );

    (proof, inputs, outputs)
}

/**
 * Full degree proof step
 *
 * @param context - the mocked rocket http server context
 * @param prover - the account proving the degree
 * @param scope - Optionally the username of the scope to use when multiple available proofs, or the first one
 * @return - http code and message from server for degree proof submission
 */
pub async fn degree_proof_step_by_scope(
    context: &GrapevineTestContext,
    prover: &mut GrapevineAccount,
    scope: Option<&String>,
) -> (u16, String) {
    // select the specific proof to build from
    let available_proofs = http_get_available_proofs(&context, prover).await;
    let available_proof = match scope {
        Some(scope) => available_proofs
            .iter()
            .find(|&proof| scope == &proof.scope)
            .unwrap(),
        None => available_proofs.first().unwrap(),
    };
    // retrieve proving data
    let degree = available_proof.degree;
    let proving_data =
        http_get_proving_data(&context, prover, &available_proof.id.to_string()).await;
    // parse
    let (mut proof, inputs, outputs) = build_degree_inputs(prover, &proving_data, degree as u8);
    // prove
    degree_proof(
        &*ARTIFACTS,
        &inputs,
        &mut proof,
        &outputs.try_into().unwrap(),
    )
    .unwrap();
    // build DegreeProofRequest
    let compressed = compress_proof(&proof);
    let degree_proof_request = DegreeProofRequest {
        proof: compressed,
        previous: available_proof.id.to_string(),
        degree: degree + 1,
    };
    // submit degree proof and return result
    http_submit_degree_proof(&context, prover, degree_proof_request).await
}

/// Request Helpers

/**
 * Construct the request body for a user creation request
 *
 * @return - the body for a user creation http request
 */
pub fn build_create_user_request(from: &GrapevineAccount) -> CreateUserRequest {
    let proof = build_identity_proof(from);
    let compressed = compress_proof(&proof);
    from.create_user_request(compressed)
}

/**
 * Signs a nonce used to authenticate user on the server
 *
 * @param user - account signing nonce
 * @return - account's signature over nonce
 */
pub fn generate_nonce_signature(user: &GrapevineAccount) -> String {
    let nonce_signature = user.sign_nonce();
    hex::encode(nonce_signature.compress())
}

/**
 * Generate a specified number of users and register them in the grapevine service
 *
 * @param num_users - the number of users to enroll
 * @return  - the registered grapevine accounts
 */
pub async fn get_users(context: &GrapevineTestContext, num_users: usize) -> Vec<GrapevineAccount> {
    let mut users = vec![];
    for i in 0..num_users {
        let username = format!("user_{}", i);
        let user = GrapevineAccount::new(username.into());
        let request = build_create_user_request(&user);
        http_create_user(&context, &request).await;
        users.push(user);
    }
    users
}

/**
 * Builds chain of relationships between accounts
 *
 * @param accounts - the accounts to build relationships between
 */
pub async fn relationship_chain(
    context: &GrapevineTestContext,
    accounts: &mut Vec<GrapevineAccount>,
) {
    for i in 0..accounts.len() - 1 {
        let request = accounts[i]
            .new_relationship_request(accounts[i + 1].username(), &accounts[i + 1].pubkey());
        http_add_relationship(&context, &mut accounts[i], &request).await;
        let request =
            accounts[i + 1].new_relationship_request(accounts[i].username(), &accounts[i].pubkey());
        http_add_relationship(&context, &mut accounts[i + 1], &request).await;
    }
}
