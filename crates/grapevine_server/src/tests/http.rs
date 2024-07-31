use crate::tests::helpers::GrapevineTestContext;
use grapevine_common::http::requests::CreateUserRequest;

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
