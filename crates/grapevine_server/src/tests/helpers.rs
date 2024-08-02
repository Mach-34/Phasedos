use crate::{catchers::bad_request, health, mongo::GrapevineDB, routes};
use grapevine_circuits::{
    inputs::GrapevineInputs,
    utils::{compress_proof, decompress_proof},
};
use grapevine_common::{account::GrapevineAccount, http::requests::CreateUserRequest, NovaProof};
use rocket::{
    fs::{relative, FileServer},
    local::asynchronous::Client,
};

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
    grapevine_circuits::nova::identity_proof(&crate::test_rocket::ARTIFACTS, &identity_inputs)
        .unwrap()
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
    let res = verify_grapevine_proof(&proof, &ARTIFACTS.params, degree as usize)
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
