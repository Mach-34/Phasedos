use crate::mongo::GrapevineDB;
use crate::tests::{
    helpers::{build_create_user_request, GrapevineTestContext},
    http::http_create_user,
};
use grapevine_common::account::GrapevineAccount;
use rocket::http::Status;

#[cfg(test)]
mod user_creation_tests {
    use super::*;

    #[rocket::async_test]
    pub async fn test_add_user() {
        // Setup
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create a new Grapevine Account
        let username = "User_A";
        let user = GrapevineAccount::new(username.into());
        // Build body for create_user_request, including constructing grapevine proof of identity
        let payload = build_create_user_request(&user);
        // transmit request to the server
        let (code, message) = http_create_user(&context, &payload).await;
        // check the outcome of the request
        assert_eq!(code, Status::Created.code);
        let expected_message = format!("Created user {}", username);
        assert_eq!(message, expected_message);

        // todo: additional verification of user existence with other routes
    }
}
