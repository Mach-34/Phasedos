use crate::{catchers::bad_request, health, mongo::GrapevineDB, routes};
use grapevine_circuits::{inputs::GrapevineInputs, utils::compress_proof};
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
