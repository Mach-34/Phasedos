use crate::tests::helpers::{generate_nonce_signature, GrapevineTestContext};
use grapevine_common::{
    account::GrapevineAccount,
    errors::GrapevineError,
    http::{
        requests::{
            CreateUserRequest, DegreeProofRequest, EmitNullifierRequest, NewRelationshipRequest,
        },
        responses::ProofMetadata,
    },
    models::{GrapevineProof, ProvingData, Relationship},
};
use rocket::http::Header;

/// Proof Requests

pub async fn http_get_available_proofs(
    context: &GrapevineTestContext,
    user: &mut GrapevineAccount,
) -> Vec<ProofMetadata> {
    let username = user.username().clone();
    let signature = generate_nonce_signature(user);

    // mock transmit the request
    let res = context
        .client
        .get("/proof/available")
        .header(Header::new("X-Authorization", signature))
        .header(Header::new("X-Username", username))
        .dispatch()
        .await
        .into_json::<Vec<ProofMetadata>>()
        .await;

    let _ = user.increment_nonce(None);
    res.unwrap()
}

pub async fn http_submit_degree_proof(
    context: &GrapevineTestContext,
    user: &mut GrapevineAccount,
    payload: DegreeProofRequest,
) -> (u16, String) {
    let serialized = bincode::serialize(&payload).unwrap();
    let username = user.username().clone();
    let signature = generate_nonce_signature(user);

    // mock transmit the request
    let res = context
        .client
        .post("/proof/degree")
        .header(Header::new("X-Authorization", signature))
        .header(Header::new("X-Username", username))
        .body(serialized)
        .dispatch()
        .await;
    let code = res.status().code;
    let message = res.into_string().await.unwrap_or(String::default());
    // Increment nonce after request
    let _ = user.increment_nonce(None);
    (code, message)
}

// @TODO: Add comments
pub async fn http_get_proof_by_scope(
    context: &GrapevineTestContext,
    user: &mut GrapevineAccount,
    scope: &String,
) -> Option<GrapevineProof> {
    let username = user.username().clone();
    let signature = generate_nonce_signature(user);
    let uri = format!("/proof/{}", scope);

    // mock transmit the request
    let res = context
        .client
        .get(uri)
        .header(Header::new("X-Authorization", signature))
        .header(Header::new("X-Username", username))
        .dispatch()
        .await;

    // increment nonce
    let _ = user.increment_nonce(None);

    // parse response
    match res.status().code {
        200 => Some(res.into_json::<GrapevineProof>().await.unwrap()),
        _ => None,
    }
}

// @TODO: Add comments
pub async fn http_get_proving_data(
    context: &GrapevineTestContext,
    user: &mut GrapevineAccount,
    proof: &String,
) -> ProvingData {
    let username = user.username().clone();
    let signature = generate_nonce_signature(user);
    let uri = format!("/proof/params/{}", proof);

    // mock transmit the request
    let res = context
        .client
        .get(uri)
        .header(Header::new("X-Authorization", signature))
        .header(Header::new("X-Username", username))
        .dispatch()
        .await
        .into_json::<ProvingData>()
        .await;

    let _ = user.increment_nonce(None);
    res.unwrap()
}

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
) -> (u16, Result<String, GrapevineError>) {
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

    if code >= 300 {
        let error_msg = res.into_json::<GrapevineError>().await.unwrap();
        (code, Err(error_msg))
    } else {
        let message = res.into_string().await.unwrap();
        (code, Ok(message))
    }
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
) -> (u16, Result<String, GrapevineError>) {
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
    // Increment nonce after request
    let _ = from.increment_nonce(None);

    if code >= 300 {
        let error_msg = res.into_json::<GrapevineError>().await.unwrap();
        (code, Err(error_msg))
    } else {
        let msg = res.into_string().await.unwrap();
        (code, Ok(msg))
    }
}

/**
 * Mock http request to get a list of pending relationships for a user
 *
 * @param context - the mocked rocket http server context
 * @param user - the account for witch pending relationships are fetched
 * @return - (http status code, returned message)
 */
pub async fn http_get_pending_relationships(
    context: &GrapevineTestContext,
    user: &mut GrapevineAccount,
) -> Result<Vec<String>, GrapevineError> {
    let username = user.username().clone();
    let signature = generate_nonce_signature(user);

    let res = context
        .client
        .get("/user/relationship/pending")
        .header(Header::new("X-Authorization", signature))
        .header(Header::new("X-Username", username))
        .dispatch()
        .await;

    let code = res.status().code;
    let _ = user.increment_nonce(None);

    if code >= 300 {
        let error_msg = res.into_json::<GrapevineError>().await.unwrap();
        Err(error_msg)
    } else {
        let pending_reqs = res.into_json::<Vec<String>>().await.unwrap();
        Ok(pending_reqs)
    }
}

/**
 * Mock http request to reject a pending relationship
 *
 * @param context - the mocked rocket http server context
 * @param user - the account to which a relationship creation request has been sent
 * @param from - the account sending the relationship creation request
 * @return - (http status code, returned message)
 */
pub async fn http_reject_relationship(
    context: &GrapevineTestContext,
    user: &mut GrapevineAccount,
    from: &str,
) -> (u16, Result<(), String>) {
    let username = user.username().clone();
    let signature = generate_nonce_signature(user);

    // mock transmit the request
    let res = context
        .client
        .post(format!("/user/relationship/reject/{}", from))
        .header(Header::new("X-Authorization", signature))
        .header(Header::new("X-Username", username))
        .dispatch()
        .await;

    let code = res.status().code;
    let _ = user.increment_nonce(None);

    if code >= 300 {
        let error_msg = res.into_string().await.unwrap();
        (code, Err(error_msg))
    } else {
        (code, Ok(()))
    }
}

/**
 * Mock http request to emit a nullifier to terminate a relationship
 *
 * @param context - the mocked rocket http server context
 * @param nullifier - plaintext nullifier to terminate relationship
 * @param sender - account terminating relationship
 * @param recipient - username of recipient account
 * @return - http status code
 */
pub async fn http_emit_nullifier(
    context: &GrapevineTestContext,
    nullifier_secret: [u8; 32],
    sender: &mut GrapevineAccount,
    recipient: &String,
) -> (u16, Result<(), String>) {
    let username = sender.username().clone();
    let signature = generate_nonce_signature(sender);

    let payload = EmitNullifierRequest {
        nullifier_secret,
        recipient: recipient.to_string(),
    };

    let serialized = bincode::serialize(&payload).unwrap();

    let res = context
        .client
        .post("/user/relationship/nullify")
        .header(Header::new("X-Authorization", signature))
        .header(Header::new("X-Username", username))
        .body(serialized)
        .dispatch()
        .await;

    // Increment nonce after request
    let _ = sender.increment_nonce(None);
    let code = res.status().code;

    if code >= 300 {
        let error_msg = res.into_string().await.unwrap();
        (code, Err(error_msg))
    } else {
        (code, Ok(()))
    }
}

/**
 * Mock http request to get an encrypted nullifier secret from db
 *
 * @param context - the mocked rocket http server context
 * @param from - account retrieving their nullifier secret
 * @param recipient - username of recipient user in relationship
 * @return - encrypted nullifier secret
 */
pub async fn http_get_nullifier_secret(
    context: &GrapevineTestContext,
    from: &mut GrapevineAccount,
    recipient: &String,
) -> [u8; 48] {
    let username = from.username().clone();
    let signature = generate_nonce_signature(from);

    // mock transmit the request
    let encrypted_nullifier_secret: [u8; 48] = context
        .client
        .get(format!("/user/{}/nullifier-secret", recipient))
        .header(Header::new("X-Authorization", signature))
        .header(Header::new("X-Username", username))
        .dispatch()
        .await
        .into_bytes()
        .await
        .unwrap()
        .try_into()
        .unwrap();

    // Increment nonce after request
    let _ = from.increment_nonce(None);

    encrypted_nullifier_secret
}

/**
 * Mock http request to get a relationship between a sender and recipient
 *
 * @param context - the mocked rocket http server context
 * @param sender - username of sender in relationship
 * @param recipient - username of recipient in relationship
 * @return - relationship struct
 */
pub async fn http_get_relationship(
    context: &GrapevineTestContext,
    sender: &String,
    recipient: &String,
) -> Relationship {
    context
        .client
        .get(format!("/user/relationship/{}/{}", recipient, sender))
        .dispatch()
        .await
        .into_json::<Relationship>()
        .await
        .unwrap()
}

/**
 * Mock http request to get a relationship between a sender and recipient
 *
 * @param context - the mocked rocket http server context
 * @param from - account checking whether relationships have been nullified
 * @return - vector of counterparty usernames that have nullified a relationship with account
 */
pub async fn http_get_nullified_relationships(
    context: &GrapevineTestContext,
    from: &mut GrapevineAccount,
) -> Vec<String> {
    let username = from.username().clone();
    let signature = generate_nonce_signature(from);

    // mock transmit the request
    let res = context
        .client
        .get("/user/relationship/nullified")
        .header(Header::new("X-Authorization", signature))
        .header(Header::new("X-Username", username))
        .dispatch()
        .await
        .into_json::<Vec<String>>()
        .await
        .unwrap();

    // Increment nonce after request
    let _ = from.increment_nonce(None);
    res
}
