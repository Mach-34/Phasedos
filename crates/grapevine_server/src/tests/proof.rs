use crate::{
    mongo::GrapevineDB,
    tests::{
        helpers::{
            build_create_user_request, build_degree_inputs, degree_proof_step_by_scope, get_users,
            relationship_chain, GrapevineTestContext, ARTIFACTS,
        },
        http::{
            http_add_relationship, http_create_user, http_emit_nullifier,
            http_get_available_proofs, http_get_nullifier_secret, http_get_proof_by_scope,
            http_get_proving_data, http_submit_degree_proof,
        },
    },
};
use grapevine_circuits::{nova::degree_proof, utils::compress_proof};
use grapevine_common::{
    account::GrapevineAccount, compat::ff_ce_to_le_bytes, http::requests::DegreeProofRequest,
};
use rocket::http::Status;

#[cfg(test)]
mod degree_proof_tests {
    use super::*;

    #[rocket::async_test]
    pub async fn test_degree_one() {
        // Setup
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // create users
        let mut users = get_users(&context, 2).await;
        // establish relationship between users
        relationship_chain(&context, &mut users).await;

        // retrieve available proofs as user_b
        let (code, _) = degree_proof_step_by_scope(&context, &mut users[1], None).await;
        assert_eq!(code, Status::Created.code);
        // ensure no proofs to build from
        let available = http_get_available_proofs(&context, &mut users[1]).await;
        assert_eq!(available.len(), 0);
    }

    #[rocket::async_test]
    pub async fn test_degree_8_linear() {
        // Setup
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // create users
        let num_users = 9;
        let mut users = get_users(&context, num_users).await;
        // establish relationship chain for users
        relationship_chain(&context, &mut users).await;
        // build proof chain to max available degree
        let scope_to_find = String::from("user_0");
        for i in 1..num_users {
            let mut prover = users.remove(i);
            let (code, _) =
                degree_proof_step_by_scope(&context, &mut prover, Some(&scope_to_find)).await;
            assert_eq!(code, Status::Created.code);
            users.insert(i, prover);
        }
    }

    #[rocket::async_test]
    pub async fn test_basic_reordering() {
        // Setup
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // create users
        let mut users = get_users(&context, 5).await;
        // create linear chain
        relationship_chain(&context, &mut users).await;
        // build proof chain
        let scope_to_find = String::from("user_0");
        for i in 1..5 {
            let mut prover = users.remove(i);
            let (code, _) =
                degree_proof_step_by_scope(&context, &mut prover, Some(&scope_to_find)).await;
            assert_eq!(code, Status::Created.code);
            users.insert(i, prover);
        }
        // ensure no prover has available for scope
        for i in 1..5 {
            let available = http_get_available_proofs(&context, &mut users[i]).await;
            let available = available
                .iter()
                .find(|&proof| &scope_to_find == &proof.scope);
            assert!(available.is_none());
        }
        // make relationship user_0 -> user_2
        let mut temp_vec = vec![users.remove(2), users.remove(0)];
        temp_vec.reverse();
        relationship_chain(&context, &mut temp_vec).await;
        users.insert(0, temp_vec.remove(0));
        users.insert(2, temp_vec.remove(0));
        // build proof from user 0 to user 2
        for i in 2..5 {
            let mut prover = users.remove(i);
            let (code, _) =
                degree_proof_step_by_scope(&context, &mut prover, Some(&scope_to_find)).await;
            assert_eq!(code, Status::Created.code);
            users.insert(i, prover);
        }
    }

    #[rocket::async_test]
    pub async fn test_nonlinear_reordering() {
        // todo: this test is disgusting and must be fixed
        // user_0
        //   |- user_1
        //        |- user_2
        //            |-user_3
        //            |   |-user_4
        //            |       |-user_5
        //            |
        //            |-user_6
        //            |   |-user_7
        //            |       |-user_8
        //            |       |-user_9
        //            |
        //            |-user_10
        //            |   |-user_11
        //            |       |-user_12
        //            |       |-user_13
        //
        // to
        // user_0
        //   |- user_1
        //        |-user_3
        //        |   |-user_4
        //        |       |-user_5
        //        |
        //        |-user_6
        //        |   |-user_7
        //        |       |-user_8
        //        |       |-user_9
        //        |
        //        |-user_10
        //        |   |-user_11
        //        |       |-user_12
        //        |       |-user_13
        //
        // Setup
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // create users
        let mut users = get_users(&context, 14).await;
        // todo: fix this bs
        // establish 0-1-2-3-4-5 chain
        let mut temp_vec = vec![
            users.remove(5),
            users.remove(4),
            users.remove(3),
            users.remove(2),
            users.remove(1),
            users.remove(0),
        ];
        temp_vec.reverse();
        relationship_chain(&context, &mut temp_vec).await;
        users.insert(0, temp_vec.remove(0));
        users.insert(1, temp_vec.remove(0));
        users.insert(2, temp_vec.remove(0));
        users.insert(3, temp_vec.remove(0));
        users.insert(4, temp_vec.remove(0));
        users.insert(5, temp_vec.remove(0));
        // establish 2-6-7-8 chain
        let mut temp_vec = vec![
            users.remove(8),
            users.remove(7),
            users.remove(6),
            users.remove(2),
        ];
        temp_vec.reverse();
        relationship_chain(&context, &mut temp_vec).await;
        users.insert(2, temp_vec.remove(0));
        users.insert(6, temp_vec.remove(0));
        users.insert(7, temp_vec.remove(0));
        users.insert(8, temp_vec.remove(0));
        // extablish 7-9
        let mut temp_vec = vec![users.remove(9), users.remove(7)];
        temp_vec.reverse();
        relationship_chain(&context, &mut temp_vec).await;
        users.insert(7, temp_vec.remove(0));
        users.insert(9, temp_vec.remove(0));
        // establish 2-10-11-12
        let mut temp_vec = vec![
            users.remove(12),
            users.remove(11),
            users.remove(10),
            users.remove(2),
        ];
        temp_vec.reverse();
        relationship_chain(&context, &mut temp_vec).await;
        users.insert(2, temp_vec.remove(0));
        users.insert(10, temp_vec.remove(0));
        users.insert(11, temp_vec.remove(0));
        users.insert(12, temp_vec.remove(0));
        // establish 11-13
        let mut temp_vec = vec![users.remove(13), users.remove(11)];
        temp_vec.reverse();
        relationship_chain(&context, &mut temp_vec).await;
        users.insert(11, temp_vec.remove(0));
        users.insert(13, temp_vec.remove(0));
        // build proof chain
        let scope_to_find = String::from("user_0");
        for i in 1..14 {
            let mut prover = users.remove(i);
            let (code, _) =
                degree_proof_step_by_scope(&context, &mut prover, Some(&scope_to_find)).await;
            assert_eq!(code, Status::Created.code);
            users.insert(i, prover);
        }

        // make relationship for user0->user2
        let mut temp_vec = vec![users.remove(2), users.remove(0)];
        temp_vec.reverse();
        relationship_chain(&context, &mut temp_vec).await;
        users.insert(0, temp_vec.remove(0));
        users.insert(2, temp_vec.remove(0));

        // update proofs
        for i in 2..14 {
            let mut prover = users.remove(i);
            let (code, _) =
                degree_proof_step_by_scope(&context, &mut prover, Some(&scope_to_find)).await;
            assert_eq!(code, Status::Created.code);
            users.insert(i, prover);
        }
    }

    #[rocket::async_test]
    pub async fn test_nullify_existing_proofs() {
        // Setup
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // create users
        let num_users = 9;
        let mut users = get_users(&context, num_users).await;
        // establish relationship chain for users
        relationship_chain(&context, &mut users).await;
        // build proof chain
        let scope_to_find = String::from("user_0");
        for i in 1..num_users {
            let mut prover = users.remove(i);
            let (code, _) =
                degree_proof_step_by_scope(&context, &mut prover, Some(&scope_to_find)).await;
            assert_eq!(code, Status::Created.code);
            users.insert(i, prover);
        }

        // check that all degree provers in the chain have proofs
        for i in 1..num_users {
            let mut user = users.remove(i);
            let proof = http_get_proof_by_scope(&context, &mut user, &scope_to_find).await;
            assert!(proof.is_some());
            users.insert(i, user);
        }
        // nullify user_4->user_5
        let nullify_target = String::from("user_5");
        let nullifier_secret_ciphertext =
            http_get_nullifier_secret(&context, &mut users[4], &nullify_target).await;
        let nullifier_secret = users[4].decrypt_nullifier_secret(nullifier_secret_ciphertext);
        _ = http_emit_nullifier(
            &context,
            ff_ce_to_le_bytes(&nullifier_secret),
            &mut users[4],
            &nullify_target,
        )
        .await;
        // check that users1->4 have proofs for the scope and users5-8 do not
        let cutoff = 4;
        for i in 1..num_users {
            let mut user = users.remove(i);
            let proof = http_get_proof_by_scope(&context, &mut user, &scope_to_find).await;
            if i <= 4 {
                assert!(proof.is_some());
            } else {
                assert!(proof.is_none());
            }
            users.insert(i, user);
        }
    }

    #[rocket::async_test]
    pub async fn test_nullify_prevent_new_proofs() {
        // Setup
        let context = GrapevineTestContext::init().await;
        GrapevineDB::drop("grapevine_mocked").await;
        // create users
        let num_users = 3;
        let mut users: Vec<GrapevineAccount> = vec![];
        for i in 0..num_users {
            let username = format!("user_{}", i);
            let user = GrapevineAccount::new(username.into());
            let request = build_create_user_request(&user);
            http_create_user(&context, &request).await;
            users.push(user);
        }
        // establish relationship chain for users
        for i in 0..num_users - 1 {
            let request =
                users[i].new_relationship_request(users[i + 1].username(), &users[i + 1].pubkey());
            http_add_relationship(&context, &mut users[i], &request).await;
            let request =
                users[i + 1].new_relationship_request(users[i].username(), &users[i].pubkey());
            http_add_relationship(&context, &mut users[i + 1], &request).await;
        }
        // prove degree 1 separations user0->user1
        let mut user_2 = users.remove(2);
        let mut user_1 = users.remove(1);
        let mut user_0 = users.remove(0);
        // select the specific proof to build from
        let available_proofs = http_get_available_proofs(&context, &mut user_1).await;
        let available_proof = available_proofs
            .iter()
            .find(|&proof| user_0.username() == &proof.scope)
            .unwrap();
        // retrieve proving data
        let proving_data =
            http_get_proving_data(&context, &mut user_1, &available_proof.id.to_string()).await;
        // parse
        let (mut proof, inputs, outputs) = build_degree_inputs(&user_1, &proving_data, 0);
        // prove
        degree_proof(
            &*ARTIFACTS,
            &inputs,
            &mut proof,
            &outputs.try_into().unwrap(),
        )
        .unwrap();
        // submit degree proof
        let compressed = compress_proof(&proof);
        let degree_proof_request = DegreeProofRequest {
            proof: compressed,
            previous: available_proof.id.to_string(),
            degree: 1,
        };
        let (code, msg) =
            http_submit_degree_proof(&context, &mut user_1, degree_proof_request).await;
        // retrieve the next degree proof
        let available_proofs = http_get_available_proofs(&context, &mut user_2).await;
        let available_proof = available_proofs
            .iter()
            .find(|&proof| user_0.username() == &proof.scope)
            .unwrap();
        // retrieve proving data
        let proving_data =
            http_get_proving_data(&context, &mut user_2, &available_proof.id.to_string()).await;
        // nullify user_0 -> user_1 relationship
        let nullifier_secret_ciphertext =
            http_get_nullifier_secret(&context, &mut user_0, user_1.username()).await;
        let nullifier_secret = user_0.decrypt_nullifier_secret(nullifier_secret_ciphertext);
        _ = http_emit_nullifier(
            &context,
            ff_ce_to_le_bytes(&nullifier_secret),
            &mut user_0,
            user_1.username(),
        )
        .await;
        // prove and submit now nullified proof
        let (mut proof, inputs, outputs) = build_degree_inputs(&user_2, &proving_data, 1);
        degree_proof(
            &*ARTIFACTS,
            &inputs,
            &mut proof,
            &outputs.try_into().unwrap(),
        )
        .unwrap();
        let compressed = compress_proof(&proof);
        let degree_proof_request = DegreeProofRequest {
            proof: compressed,
            previous: available_proof.id.to_string(),
            degree: 2,
        };
        // check expected output
        let (code, msg) =
            http_submit_degree_proof(&context, &mut user_2, degree_proof_request).await;
        let expected_code = Status::BadRequest.code;
        assert_eq!(code, expected_code);
        let expected_message = String::from("{\"ProofFailed\":\"Contains emitted nullifiers\"}");
        assert_eq!(msg, expected_message);
    }
}
