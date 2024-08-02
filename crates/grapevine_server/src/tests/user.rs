use crate::mongo::GrapevineDB;
use crate::tests::{
    helpers::{build_create_user_request, GrapevineTestContext},
    http::{
        http_add_relationship, http_create_user, http_emit_nullifier, http_get_nullifier_secret,
    },
};
use grapevine_common::{
    account::GrapevineAccount,
    compat::{convert_ff_ce_to_ff, ff_ce_to_le_bytes},
};
use rocket::http::Status;

#[cfg(test)]
mod user_creation_tests {
    use super::*;

    use grapevine_common::crypto::pubkey_to_address;

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

    #[rocket::async_test]
    pub async fn test_add_user_no_duplicate() {
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
        assert_eq!(message, String::from("{\"UserExists\":\"User_A\"}"));

        // try with duplicate username
        let user_duplicate_name = GrapevineAccount::new(username.into());
        let payload = build_create_user_request(&user_duplicate_name);
        let (code, message) = http_create_user(&context, &payload).await;
        assert_eq!(code, Status::Conflict.code);
        assert_eq!(message, String::from("{\"UsernameExists\":\"User_A\"}"));

        // try with duplicate pubkey
        let user_duplicate_pubkey =
            GrapevineAccount::from_repr("User_B".into(), *user.private_key_raw(), 0);
        let payload = build_create_user_request(&user_duplicate_pubkey);
        let (code, message) = http_create_user(&context, &payload).await;
        assert_eq!(code, Status::Conflict.code);
        let pubkey = format!("0x{}", hex::encode(user.pubkey().compress()));
        let expected_message = format!("{{\"PubkeyExists\":\"{}\"}}", pubkey);
        assert_eq!(message, expected_message);
    }

    #[rocket::async_test]
    pub async fn test_add_user_bad_proof_output() {
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
        let expected_message = format!(
            "{{\"ProofFailed\":\"Expected identity scope to equal 0x{}\"}}",
            expected_scope
        );
        assert_eq!(code, Status::BadRequest.code);
        assert_eq!(message, expected_message);
    }

    // todo: check malformed inputs
}

#[cfg(test)]
mod relationship_tests {
    use super::*;

    #[rocket::async_test]
    pub async fn test_relationship_creation() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create a request where proof creator is different from asserted pubkey
        let mut user_a = GrapevineAccount::new("user_a".into());

        let mut user_b = GrapevineAccount::new("user_b".into());

        let user_request_a = build_create_user_request(&user_a);
        let user_request_b = build_create_user_request(&user_b);
        http_create_user(&context, &user_request_a).await;
        http_create_user(&context, &user_request_b).await;

        // add relationship as user_a to user_b
        let request = user_a.new_relationship_request(user_b.username(), &user_b.pubkey());

        http_add_relationship(&context, &mut user_a, &request).await;

        // accept relation from user_a as user_b
        let request = user_b.new_relationship_request(user_a.username(), &user_a.pubkey());
        let expected_nullifier_secret_ciphertext = request.nullifier_secret_ciphertext;
        http_add_relationship(&context, &mut user_b, &request).await;

        // check stored nullifier secret integrity
        let nullifier_secret_ciphertext =
            http_get_nullifier_secret(&context, &mut user_b, user_a.username()).await;
        let expected_secret = user_b.decrypt_nullifier_secret(expected_nullifier_secret_ciphertext);
        let empirical_secret = user_b.decrypt_nullifier_secret(nullifier_secret_ciphertext);
        assert_eq!(expected_secret, empirical_secret);
    }

    #[ignore]
    #[rocket::async_test]
    pub async fn test_reject_relationship() {
        todo!("Unimplemented")
    }

    #[ignore]
    #[rocket::async_test]
    pub async fn test_no_relationship_with_self() {
        todo!("Unimplemented")
    }

    #[ignore]
    #[rocket::async_test]
    pub async fn test_cannot_reject_active_relationship() {
        // nullifiy, don't reject
        todo!("Unimplemented")
    }

    #[ignore]
    #[rocket::async_test]
    pub async fn test_cannot_reject_nonexistent_relationship() {
        todo!("Unimplemented")
    }

    #[ignore]
    #[rocket::async_test]
    pub async fn test_cannot_act_nullified_relationship() {
        todo!("Unimplemented")
    }

    #[ignore]
    #[rocket::async_test]
    pub async fn test_cannot_request_already_active_relationship() {
        todo!("Unimplemented")
    }

    #[rocket::async_test]
    pub async fn test_nullifier_emission() {
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // Create a request where proof creator is different from asserted pubkey
        let mut user_a = GrapevineAccount::new("user_a".into());

        let mut user_b = GrapevineAccount::new("user_b".into());

        let user_request_a = build_create_user_request(&user_a);
        let user_request_b = build_create_user_request(&user_b);
        http_create_user(&context, &user_request_a).await;
        http_create_user(&context, &user_request_b).await;

        // add relationship as user_a to user_b
        let user_a_relationship_request =
            user_a.new_relationship_request(user_b.username(), &user_b.pubkey());

        http_add_relationship(&context, &mut user_a, &user_a_relationship_request).await;

        // accept relation from user_a as user_b
        let user_b_relationship_request =
            user_b.new_relationship_request(user_a.username(), &user_a.pubkey());

        http_add_relationship(&context, &mut user_b, &user_b_relationship_request).await;

        let encrypted_nullifier_secret =
            http_get_nullifier_secret(&context, &mut user_a, user_b.username()).await;

        let nullifier_secret = user_a.decrypt_nullifier_secret(encrypted_nullifier_secret);

        // emit nullifier as user_a
        let code = http_emit_nullifier(
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

    #[ignore]
    #[rocket::async_test]
    pub async fn test_cannot_nullify_pending_relationship() {
        todo!("Unimplemented")
    }

    #[ignore]
    #[rocket::async_test]
    pub async fn test_cannot_nullify_nullified_relationship() {
        todo!("Unimplemented")
    }

    #[ignore]
    #[rocket::async_test]
    pub async fn test_cannot_nullify_nonexistent_relationship() {
        todo!("Unimplemented")
    }
}
