use crate::tests::helpers::{generate_nonce_signature, GrapevineTestContext};
use grapevine_common::{
    account::GrapevineAccount,
    http::requests::{CreateUserRequest, NewRelationshipRequest},
};
use rocket::http::Header;

/// Proof Requests

/// User Requests

/**
 * Mock http request to create a new user
 *
 * @param context - the mocked rocket http server context
 * @param payload - the body of the request
 * @return - (http status code, returned message)
 */
pub async fn http_create_user(
    context: &GrapevineTestContext,
    payload: &CreateUserRequest,
) -> (u16, String) {
    // serialze the payload
    let serialized = bincode::serialize(&payload).unwrap();
    // mock transmit the request
    let res = context
        .client
        .post("/proof/identity")
        .body(serialized)
        .dispatch()
        .await;
    let code = res.status().code;
    let message = res.into_string().await.unwrap();
    (code, message)
}

/**
 * Mock http request to create a new relationship
 *
 * @param context - the mocked rocket http server context
 * @param from - the account sending the relationship creation request
 * @param payload - the body of the request
 * @return - (http status code, returned message)
 */
pub async fn http_add_relationship(
    context: &GrapevineTestContext,
    from: &mut GrapevineAccount,
    payload: &NewRelationshipRequest,
) -> (u16, String) {
    // serialize the payload
    let serialized = bincode::serialize(&payload).unwrap();

    let username = from.username().clone();
    let signature = generate_nonce_signature(from);

    // mock transmit the request
    let res = context
        .client
        .post("/user/relationship/add")
        .header(Header::new("X-Authorization", signature))
        .header(Header::new("X-Username", username))
        .body(serialized)
        .dispatch()
        .await;
    let code = res.status().code;
    let message = res.into_string().await.unwrap();
    // Increment nonce after request
    let _ = from.increment_nonce(None);
    (code, message)
}
