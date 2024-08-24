use crate::mongo::GrapevineDB;
use crate::tests::{
    helpers::{build_create_user_request, GrapevineTestContext},
    http::{
        http_add_relationship, http_create_user, http_emit_nullifier, http_get_nullifier_secret,
        http_get_pending_relationships,
    },
};
use grapevine_common::{
    account::GrapevineAccount,
    compat::{convert_ff_ce_to_ff, ff_ce_to_le_bytes},
};
use rocket::http::{Header, Status};

#[cfg(test)]
mod user_creation_tests {
    use crate::tests::helpers::generate_nonce_signature;

    use super::*;

    use grapevine_common::{crypto::pubkey_to_address, errors::GrapevineError};
    use rocket::http::Header;

    #[rocket::async_test]
    #[ignore]
    pub async fn test_body_size_exceeded() {
        todo!("")
    }

    #[rocket::async_test]
    pub async fn test_invalid_request_body() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;

        let user = GrapevineAccount::new(String::from("username"));
        let username = user.username().clone();
        let signature = generate_nonce_signature(&user);

        let res = context
            .client
            .post("/proof/identity")
            .body(vec![])
            .header(Header::new("X-Authorization", signature))
            .header(Header::new("X-Username", username.clone()))
            .dispatch()
            .await;

        assert_eq!(res.status().code, 400);

        let serde_error = GrapevineError::SerdeError(String::from("CreateUserRequest"));
        let msg = res.into_json::<GrapevineError>().await.unwrap();
        assert_eq!(serde_error.to_string(), msg.to_string());
    }

    #[rocket::async_test]
    pub async fn test_invalid_username_length() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;

        let long_username = String::from("usernameusernameusernameusernameusername");
        let user = GrapevineAccount::new(String::from("username"));

        let mut payload = build_create_user_request(&user);

        payload.username = long_username.clone();

        let res = http_create_user(&context, &payload).await;

        assert_eq!(res.0, 400);
        assert_eq!(
            res.1.unwrap_err().to_string(),
            GrapevineError::UsernameTooLong(long_username).to_string()
        );
    }

    #[rocket::async_test]
    pub async fn test_non_ascii_characters() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;

        let non_ascii_username = String::from("user😃🤪");
        let user = GrapevineAccount::new(String::from("username"));

        let mut payload = build_create_user_request(&user);

        payload.username = non_ascii_username.clone();

        let res = http_create_user(&context, &payload).await;

        assert_eq!(res.0, 400);
        assert_eq!(
            res.1.unwrap_err().to_string(),
            GrapevineError::UsernameNotAscii(non_ascii_username).to_string()
        );
    }

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
        assert_eq!(message.unwrap(), expected_message);
    }

    #[rocket::async_test]
    pub async fn test_add_user_duplicate() {
        // Setup
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create and enroll a grapevine account
        let username = "User_A";
        let user = GrapevineAccount::new(username.into());
        let payload = build_create_user_request(&user);
        _ = http_create_user(&context, &payload).await;

        // try with duplicate user
        let (code, message) = http_create_user(&context, &payload).await;
        assert_eq!(code, Status::Conflict.code);
        assert_eq!(
            message.unwrap_err().to_string(),
            GrapevineError::UserExists(String::from(username)).to_string()
        );
    }

    #[rocket::async_test]
    pub async fn test_add_user_duplicate_username() {
        // Setup
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create and enroll a grapevine account
        let username = "User_A";
        let user = GrapevineAccount::new(username.into());
        let payload = build_create_user_request(&user);
        _ = http_create_user(&context, &payload).await;

        let user_duplicate_name = GrapevineAccount::new(username.into());
        let payload = build_create_user_request(&user_duplicate_name);
        let (code, message) = http_create_user(&context, &payload).await;
        assert_eq!(code, Status::Conflict.code);
        assert_eq!(
            message.unwrap_err().to_string(),
            GrapevineError::UsernameExists(username.into()).to_string()
        );
    }

    #[rocket::async_test]
    pub async fn test_add_user_duplicate_pubkey() {
        // Setup
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create and enroll a grapevine account
        let username = "User_A";
        let user = GrapevineAccount::new(username.into());
        let payload = build_create_user_request(&user);
        _ = http_create_user(&context, &payload).await;

        // try with duplicate pubkey
        let user_duplicate_pubkey =
            GrapevineAccount::from_repr("User_B".into(), *user.private_key_raw(), 0);
        let payload = build_create_user_request(&user_duplicate_pubkey);
        let (code, message) = http_create_user(&context, &payload).await;
        assert_eq!(code, Status::Conflict.code);
        let pubkey = format!("0x{}", hex::encode(user.pubkey().compress()));
        let expected_message = GrapevineError::PubkeyExists(pubkey);
        assert_eq!(
            message.unwrap_err().to_string(),
            expected_message.to_string()
        );
    }

    #[rocket::async_test]
    #[ignore]
    pub async fn test_proof_verification_failed() {
        todo!("");
    }

    #[rocket::async_test]
    pub async fn test_proof_verification_failed_identity() {
        // Setup
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create a request where proof creator is different from asserted pubkey
        let username = "User_A";
        let user = GrapevineAccount::new(username.into());
        let mut payload = build_create_user_request(&user);
        let user_2 = GrapevineAccount::new(username.into());
        payload.pubkey = user_2.pubkey().compress();
        let (code, message) = http_create_user(&context, &payload).await;
        let expected_scope =
            hex::encode(convert_ff_ce_to_ff(&pubkey_to_address(&user_2.pubkey())).to_bytes());

        let expected_message = format!("Expected identity scope to equal 0x{}", expected_scope);
        assert_eq!(code, Status::BadRequest.code);
        assert_eq!(
            message.unwrap_err().to_string(),
            GrapevineError::ProofFailed(expected_message).to_string()
        );
    }

    #[rocket::async_test]
    #[ignore]
    pub async fn test_proof_verification_failed_relation() {
        todo!("");
    }
}

#[cfg(test)]
mod relationship_creation_tests {
    use grapevine_common::errors::GrapevineError;

    use crate::tests::helpers::generate_nonce_signature;

    use super::*;

    #[ignore]
    #[rocket::async_test]
    pub async fn test_relationship_bodysize_exceeded() {
        todo!("Unimplimented");
    }

    #[ignore]
    #[rocket::async_test]
    pub async fn test_relationship_on_nonexistent_user() {
        todo!("Unimplemented");
    }

    #[rocket::async_test]
    pub async fn test_relationship_creation_invalid_req_body() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create a request where proof creator is different from asserted pubkey
        let mut user_a = GrapevineAccount::new("user_a".into());

        let user_request_a = build_create_user_request(&user_a);
        _ = http_create_user(&context, &user_request_a).await;

        let username = user_a.username().clone();
        let signature = generate_nonce_signature(&user_a);

        let res = context
            .client
            .post("/user/relationship/add")
            .header(Header::new("X-Authorization", signature))
            .header(Header::new("X-Username", username))
            .body(vec![])
            .dispatch()
            .await;

        assert_eq!(res.status().code, 400);
        let msg = res.into_json::<GrapevineError>().await.unwrap();
        let expected = GrapevineError::SerdeError(String::from("NewRelationshipRequest"));
        assert_eq!(expected.to_string(), msg.to_string());
    }

    #[rocket::async_test]
    pub async fn test_no_relationship_with_self() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create a request where proof creator is different from asserted pubkey
        let mut user_a = GrapevineAccount::new("user_a".into());

        let user_request = build_create_user_request(&user_a);
        _ = http_create_user(&context, &user_request).await;
        let request = user_a.new_relationship_request(user_a.username(), &user_a.pubkey());

        let res = http_add_relationship(&context, &mut user_a, &request).await;
        assert_eq!(res.0, 400);
        assert_eq!(
            GrapevineError::RelationshipSenderIsTarget.to_string(),
            res.1.unwrap_err().to_string()
        );
    }

    #[rocket::async_test]
    pub async fn test_relationship_creation() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create a request where proof creator is different from asserted pubkey
        let mut user_a = GrapevineAccount::new("user_a".into());

        let mut user_b = GrapevineAccount::new("user_b".into());

        let user_request_a = build_create_user_request(&user_a);
        let user_request_b = build_create_user_request(&user_b);
        _ = http_create_user(&context, &user_request_a).await;
        _ = http_create_user(&context, &user_request_b).await;

        // add relationship as user_a to user_b
        let request = user_a.new_relationship_request(user_b.username(), &user_b.pubkey());

        _ = http_add_relationship(&context, &mut user_a, &request).await;

        // accept relation from user_a as user_b
        let request = user_b.new_relationship_request(user_a.username(), &user_a.pubkey());
        let expected_nullifier_secret_ciphertext = request.nullifier_secret_ciphertext;
        _ = http_add_relationship(&context, &mut user_b, &request).await;

        // check stored nullifier secret integrity
        let nullifier_secret_ciphertext =
            http_get_nullifier_secret(&context, &mut user_b, user_a.username()).await;
        let expected_secret = user_b.decrypt_nullifier_secret(expected_nullifier_secret_ciphertext);
        let empirical_secret = user_b.decrypt_nullifier_secret(nullifier_secret_ciphertext);
        assert_eq!(expected_secret, empirical_secret);
    }

    #[ignore]
    #[rocket::async_test]
    pub async fn test_cannot_request_already_active_relationship() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create a request where proof creator is different from asserted pubkey
        let mut user_a = GrapevineAccount::new("user_a".into());

        let mut user_b = GrapevineAccount::new("user_b".into());

        let user_request_a = build_create_user_request(&user_a);
        let user_request_b = build_create_user_request(&user_b);
        _ = http_create_user(&context, &user_request_a).await;
        _ = http_create_user(&context, &user_request_b).await;

        // add relationship as user_a to user_b
        let request = user_a.new_relationship_request(user_b.username(), &user_b.pubkey());

        _ = http_add_relationship(&context, &mut user_a, &request).await;

        // accept relation from user_a as user_b
        let request = user_b.new_relationship_request(user_a.username(), &user_a.pubkey());
        _ = http_add_relationship(&context, &mut user_b, &request).await;

        // attempt to add relationship between user_a and user_b again
        let duplicate_request =
            user_a.new_relationship_request(user_b.username(), &user_b.pubkey());
        let res = http_add_relationship(&context, &mut user_a, &duplicate_request).await;
        println!("Res: {:?}", res);
    }
}

#[cfg(test)]
mod relationship_rejection_tests {

    use crate::tests::http::http_reject_relationship;

    use super::*;

    #[rocket::async_test]
    pub async fn test_reject_relationship() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create a request where proof creator is different from asserted pubkey
        let mut user_a = GrapevineAccount::new("user_a".into());

        let mut user_b = GrapevineAccount::new("user_b".into());

        let user_request_a = build_create_user_request(&user_a);
        let user_request_b = build_create_user_request(&user_b);
        _ = http_create_user(&context, &user_request_a).await;
        _ = http_create_user(&context, &user_request_b).await;

        // add relationship as User A to User B
        let request = user_a.new_relationship_request(user_b.username(), &user_b.pubkey());

        _ = http_add_relationship(&context, &mut user_a, &request).await;

        // list pending User B
        let pending_res = http_get_pending_relationships(&context, &mut user_b).await;
        assert_eq!(pending_res.unwrap().len(), 1);

        // reject User A's request as User B
        let reject_res = http_reject_relationship(&context, &mut user_b, user_a.username()).await;
        assert!(reject_res.1.is_ok());

        // list pending User B
        let pending_res_after = http_get_pending_relationships(&context, &mut user_b).await;
        assert_eq!(pending_res_after.unwrap().len(), 0);
    }

    #[rocket::async_test]
    pub async fn test_cannot_reject_nonexistent_relationship() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create a request where proof creator is different from asserted pubkey
        let user_a = GrapevineAccount::new("user_a".into());
        let mut user_b = GrapevineAccount::new("user_b".into());

        let user_request_a = build_create_user_request(&user_a);
        let user_request_b = build_create_user_request(&user_b);
        _ = http_create_user(&context, &user_request_a).await;
        _ = http_create_user(&context, &user_request_b).await;

        // attempt to reject a relationship with user_a as user_b
        let expected = "No pending relationship exists from fakeusername to user_b";
        let (code, msg) = http_reject_relationship(&context, &mut user_b, "fakeusername").await;
        assert_eq!(code, 404);
        assert_eq!(expected, msg.unwrap_err());
    }

    #[rocket::async_test]
    pub async fn test_cannot_reject_active_relationship() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create a request where proof creator is different from asserted pubkey
        let mut user_a = GrapevineAccount::new("user_a".into());

        let mut user_b = GrapevineAccount::new("user_b".into());

        let user_request_a = build_create_user_request(&user_a);
        let user_request_b = build_create_user_request(&user_b);
        _ = http_create_user(&context, &user_request_a).await;
        _ = http_create_user(&context, &user_request_b).await;

        // add relationship as user_a to user_b
        let request = user_a.new_relationship_request(user_b.username(), &user_b.pubkey());

        _ = http_add_relationship(&context, &mut user_a, &request).await;

        let request = user_b.new_relationship_request(user_a.username(), &user_a.pubkey());
        // accept relation from user_a as user_b
        _ = http_add_relationship(&context, &mut user_b, &request).await;

        // attempt to reject a relationship with user_a as user_b
        let expected = "No pending relationship exists from fakeusername to user_b";
        let (code, msg) = http_reject_relationship(&context, &mut user_b, "fakeusername").await;
        assert_eq!(code, 404);
        assert_eq!(expected, msg.unwrap_err());
    }

    #[rocket::async_test]
    pub async fn test_cannot_reject_nullified_relationship() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create a request where proof creator is different from asserted pubkey
        let mut user_a = GrapevineAccount::new("user_a".into());

        let mut user_b = GrapevineAccount::new("user_b".into());

        let user_request_a = build_create_user_request(&user_a);
        let user_request_b = build_create_user_request(&user_b);
        _ = http_create_user(&context, &user_request_a).await;
        _ = http_create_user(&context, &user_request_b).await;

        // add relationship as user_a to user_b
        let request = user_a.new_relationship_request(user_b.username(), &user_b.pubkey());

        _ = http_add_relationship(&context, &mut user_a, &request).await;

        let request = user_b.new_relationship_request(user_a.username(), &user_a.pubkey());
        // accept relation from user_a as user_b
        _ = http_add_relationship(&context, &mut user_b, &request).await;

        // nullify relationship as user_b with user_a
        let encrypted_nullifier_secret =
            http_get_nullifier_secret(&context, &mut user_b, user_a.username()).await;

        let nullifier_secret = user_b.decrypt_nullifier_secret(encrypted_nullifier_secret);

        // emit nullifier as user_b
        _ = http_emit_nullifier(
            &context,
            ff_ce_to_le_bytes(&nullifier_secret),
            &mut user_b,
            user_a.username(),
        )
        .await;

        // attempt to reject relatioship as User B
        let expected = "No pending relationship exists from user_a to user_b";
        let (code, msg) = http_reject_relationship(&context, &mut user_b, user_a.username()).await;
        assert_eq!(code, 404);
        assert_eq!(expected, msg.unwrap_err());
    }
}

#[cfg(test)]
mod relationship_nullification_test {

    use super::*;

    #[rocket::async_test]
    pub async fn test_nullifier_emission() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create a request where proof creator is different from asserted pubkey
        let mut user_a = GrapevineAccount::new("user_a".into());

        let mut user_b = GrapevineAccount::new("user_b".into());

        let user_request_a = build_create_user_request(&user_a);
        let user_request_b = build_create_user_request(&user_b);
        _ = http_create_user(&context, &user_request_a).await;
        _ = http_create_user(&context, &user_request_b).await;

        // add relationship as user_a to user_b
        let user_a_relationship_request =
            user_a.new_relationship_request(user_b.username(), &user_b.pubkey());

        _ = http_add_relationship(&context, &mut user_a, &user_a_relationship_request).await;

        // accept relation from user_a as user_b
        let user_b_relationship_request =
            user_b.new_relationship_request(user_a.username(), &user_a.pubkey());

        _ = http_add_relationship(&context, &mut user_b, &user_b_relationship_request).await;

        let encrypted_nullifier_secret =
            http_get_nullifier_secret(&context, &mut user_a, user_b.username()).await;

        let nullifier_secret = user_a.decrypt_nullifier_secret(encrypted_nullifier_secret);

        // emit nullifier as user_a
        let (code, _) = http_emit_nullifier(
            &context,
            ff_ce_to_le_bytes(&nullifier_secret),
            &mut user_a,
            user_b.username(),
        )
        .await;
        println!("Code: {}", code);
        let expected_code = Status::Created.code;
        assert_eq!(
            expected_code, code,
            "Expected HTTP::Created on nullifier emission"
        );

        // confirm relationship now has emitted nullifier
        // TODO: FIX
        // let relationship =
        //     http_get_relationship(&context, user_b.username(), user_a.username()).await;
        // assert!(
        //     relationship.emitted_nullifier.is_some(),
        //     "No nullifier emitted"
        // );
    }

    #[rocket::async_test]
    pub async fn test_cannot_nullify_pending_relationship() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create a request where proof creator is different from asserted pubkey
        let mut user_a = GrapevineAccount::new("user_a".into());

        let user_b = GrapevineAccount::new("user_b".into());

        let user_request_a = build_create_user_request(&user_a);
        let user_request_b = build_create_user_request(&user_b);
        _ = http_create_user(&context, &user_request_a).await;
        _ = http_create_user(&context, &user_request_b).await;

        // add relationship as user_a to user_b
        let relationship_request =
            user_a.new_relationship_request(user_b.username(), &user_b.pubkey());

        _ = http_add_relationship(&context, &mut user_a, &relationship_request).await;

        // nullify relationship as user_a with user_b
        let encrypted_nullifier_secret =
            http_get_nullifier_secret(&context, &mut user_a, user_b.username()).await;

        let nullifier_secret = user_a.decrypt_nullifier_secret(encrypted_nullifier_secret);

        // attempt to nullify pending relationship from user_a to user_b
        let expected = "No active relationship exists from user_a to user_b";
        let (code, msg) = http_emit_nullifier(
            &context,
            ff_ce_to_le_bytes(&nullifier_secret),
            &mut user_a,
            user_b.username(),
        )
        .await;
        assert_eq!(code, 404);
        assert_eq!(msg.unwrap_err(), expected);
    }

    #[rocket::async_test]
    pub async fn test_cannot_nullify_nullified_relationship() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create a request where proof creator is different from asserted pubkey
        let mut user_a = GrapevineAccount::new("user_a".into());

        let mut user_b = GrapevineAccount::new("user_b".into());

        let user_request_a = build_create_user_request(&user_a);
        let user_request_b = build_create_user_request(&user_b);
        _ = http_create_user(&context, &user_request_a).await;
        _ = http_create_user(&context, &user_request_b).await;

        // add relationship as user_a to user_b
        let user_a_relationship_request =
            user_a.new_relationship_request(user_b.username(), &user_b.pubkey());

        _ = http_add_relationship(&context, &mut user_a, &user_a_relationship_request).await;

        // accept relation from user_a as user_b
        let user_b_relationship_request =
            user_b.new_relationship_request(user_a.username(), &user_a.pubkey());

        _ = http_add_relationship(&context, &mut user_b, &user_b_relationship_request).await;

        // nullify relationship as user_a with user_b
        let encrypted_nullifier_secret =
            http_get_nullifier_secret(&context, &mut user_a, user_b.username()).await;

        let nullifier_secret = user_a.decrypt_nullifier_secret(encrypted_nullifier_secret);

        // nullify pending relationship from user_a to user_b
        _ = http_emit_nullifier(
            &context,
            ff_ce_to_le_bytes(&nullifier_secret),
            &mut user_a,
            user_b.username(),
        )
        .await;

        // attempt to nullify nullified relationship
        let expected = "\"RelationshipNullified\"";
        let (code, msg) = http_emit_nullifier(
            &context,
            ff_ce_to_le_bytes(&nullifier_secret),
            &mut user_a,
            user_b.username(),
        )
        .await;
        assert_eq!(code, 409);
        assert_eq!(expected, msg.unwrap_err());
    }

    #[rocket::async_test]
    pub async fn test_cannot_nullify_nonexistent_relationship() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create a request where proof creator is different from asserted pubkey
        let mut user_a = GrapevineAccount::new("user_a".into());

        let mut user_b = GrapevineAccount::new("user_b".into());

        let user_request_a = build_create_user_request(&user_a);
        let user_request_b = build_create_user_request(&user_b);
        _ = http_create_user(&context, &user_request_a).await;
        _ = http_create_user(&context, &user_request_b).await;

        let relationship_request =
            user_a.new_relationship_request(user_b.username(), &user_b.pubkey());

        let nullifier_secret =
            user_a.decrypt_nullifier_secret(relationship_request.nullifier_secret_ciphertext);

        let expected = "No active relationship exists from user_a to user_b";
        let (code, msg) = http_emit_nullifier(
            &context,
            ff_ce_to_le_bytes(&nullifier_secret),
            &mut user_a,
            user_b.username(),
        )
        .await;
        assert_eq!(code, 404);
        assert_eq!(msg.unwrap_err(), expected);
    }
}
