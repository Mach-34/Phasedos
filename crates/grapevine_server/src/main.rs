#[macro_use]
extern crate rocket;
// use catchers::{bad_request, not_found, unauthorized};
use lazy_static::lazy_static;
use mongo::GrapevineDB;
use mongodb::bson::doc;
use rocket::fs::{relative, FileServer};

mod catchers;
mod guards;
mod mongo;
mod routes;
mod utils;

lazy_static! {
    static ref MONGODB_URI: String = String::from(env!("MONGODB_URI"));
    static ref DATABASE_NAME: String = String::from(env!("DATABASE_NAME"));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // connect to mongodb
    let mongo = GrapevineDB::init(&*DATABASE_NAME, &*MONGODB_URI).await;
    // Initialize logger
    tracing_subscriber::fmt::init();
    // TODO: Route formatting/ segmenting logic
    rocket::build()
        // add mongodb client to context
        .manage(mongo)
        // mount user routes
        .mount("/user", &**routes::USER_ROUTES)
        // mount proof routes
        .mount("/proof", &**routes::PROOF_ROUTES)
        // mount artifact file server
        .mount("/static", FileServer::from(relative!("static")))
        // mount test methods (TO BE REMOVED)
        .mount("/test", routes![health])
        // register request guards
        // .register("/", catchers![bad_request, not_found, unauthorized])
        .launch()
        .await?;
    Ok(())
}

#[get("/health")]
async fn health() -> &'static str {
    "Hello, world!"
}

#[cfg(test)]
mod test_rocket {
    use self::utils::{use_public_params, use_r1cs, use_wasm};

    use super::*;
    use grapevine_circuits::{
        inputs::GrapevineArtifacts,
        utils::{compress_proof, decompress_proof},
    };
    use grapevine_common::{
        account::GrapevineAccount,
        auth_secret::AuthSecretEncrypted,
        compat::ff_ce_to_le_bytes,
        http::{
            requests::{CreateUserRequest, DegreeProofRequest, NewRelationshipRequest},
            responses::DegreeData,
        },
        models::User,
        utils::random_fr,
    };
    use lazy_static::lazy_static;
    use rocket::{
        form::validate::Contains,
        http::{ContentType, Header, Status},
        local::asynchronous::Client,
    };
    use std::sync::Mutex;
    use test_helper::{
        build_create_user_request, http_add_relationship, http_create_user, http_emit_nullifier,
        http_get_nullifier_secret, http_get_relationship,
    };

    lazy_static! {
        static ref USERS: Mutex<Vec<GrapevineAccount>> = Mutex::new(vec![]);
        static ref ARTIFACTS: GrapevineArtifacts = GrapevineArtifacts {
            params: use_public_params().unwrap(),
            r1cs: use_r1cs().unwrap(),
            wasm_path: use_wasm().unwrap()
        };
    }

    struct GrapevineTestContext {
        client: Client,
    }

    impl GrapevineTestContext {
        async fn init() -> Self {
            let database_name = String::from("grapevine_mocked");
            let mongo = GrapevineDB::init(&database_name, &*MONGODB_URI).await;
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
                .mount("/static", FileServer::from(relative!("static")));
            // .register("/", catchers![bad_request, not_found, unauthorized]);

            GrapevineTestContext {
                client: Client::tracked(rocket).await.unwrap(),
            }
        }
    }

    mod test_helper {
        use super::*;
        use babyjubjub_rs::{decompress_point, decompress_signature};
        use ff::PrimeField;
        use grapevine_circuits::{
            inputs::{GrapevineInputs, GrapevineOutputs},
            nova::{degree_proof, verify_grapevine_proof},
            utils::compress_proof,
        };
        use grapevine_common::{
            account::GrapevineAccount,
            http::requests::{CreateUserRequest, EmitNullifierRequest},
            models::{AvailableProofs, GrapevineProof, ProvingData, Relationship},
            Fr, NovaProof,
        };

        /**
         * Generate a specified number of users and register them in the grapevine service
         *
         * @param num_users - the number of users to enroll
         * @return  - the registered grapevine accounts
         */
        pub async fn get_users(
            context: &GrapevineTestContext,
            num_users: usize,
        ) -> Vec<GrapevineAccount> {
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
         * Build a grapevine identity proof (degree 0) given a grapevine account
         *
         * @return the grapevine proof
         */
        pub fn build_identity_proof(from: &GrapevineAccount) -> NovaProof {
            // get inputs
            let private_key = &from.private_key();
            let identity_inputs = GrapevineInputs::identity_step(private_key);
            grapevine_circuits::nova::identity_proof(&ARTIFACTS, &identity_inputs).unwrap()
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
            println!("Available Proofs: {:?}", available_proofs);
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
            let (mut proof, inputs, outputs) =
                build_degree_inputs(prover, &proving_data, degree as u8);
            // prove
            degree_proof(
                &ARTIFACTS,
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
        fn generate_nonce_signature(user: &GrapevineAccount) -> String {
            let nonce_signature = user.sign_nonce();
            hex::encode(nonce_signature.compress())
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
                let request = accounts[i].new_relationship_request(
                    accounts[i + 1].username(),
                    &accounts[i + 1].pubkey(),
                );
                http_add_relationship(&context, &mut accounts[i], &request).await;
                let request = accounts[i + 1]
                    .new_relationship_request(accounts[i].username(), &accounts[i].pubkey());
                http_add_relationship(&context, &mut accounts[i + 1], &request).await;
            }
        }

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
            nullifier: [u8; 32],
            sender: &mut GrapevineAccount,
            recipient: &String,
        ) -> u16 {
            let username = sender.username().clone();
            let signature = generate_nonce_signature(sender);

            let payload = EmitNullifierRequest {
                nullifier,
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

            res.status().code
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
                .get(format!("/user/nullifier-secret/{}", recipient))
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

        pub async fn http_get_available_proofs(
            context: &GrapevineTestContext,
            user: &mut GrapevineAccount,
        ) -> Vec<AvailableProofs> {
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
                .into_json::<Vec<AvailableProofs>>()
                .await;

            let _ = user.increment_nonce(None);
            res.unwrap()
        }

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

        pub async fn http_get_proof_by_scope(
            context: &GrapevineTestContext,
            user: &mut GrapevineAccount,
            scope: &String,
        ) -> Option<GrapevineProof> {
            let username = user.username().clone();
            let signature = generate_nonce_signature(user);
            let uri = format!("/proof/scope/{}", scope);

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
        // async fn http_get_relationships(
        //     context: &GrapevineTestContext,
        //     user: &mut GrapevineAccount,
        //     active: bool,
        // ) -> Option<Vec<String>> {
        //     let username = user.username().clone();
        //     let signature = generate_nonce_signature(user);
        //     let route = if active { "active" } else { "pending" };
        //     let res = context
        //         .client
        //         .get(format!("/user/relationship/{}", route))
        //         .header(Header::new("X-Authorization", signature))
        //         .header(Header::new("X-Username", username))
        //         .dispatch()
        //         .await
        //         .into_json::<Vec<String>>()
        //         .await;

        //     // Increment nonce after request
        //     let _ = user.increment_nonce(None);
        //     res
        // }
    }

    #[cfg(test)]
    mod user_creation_tests {
        use super::*;
        use grapevine_common::compat::convert_ff_ce_to_ff;
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
            let expected_secret =
                user_b.decrypt_nullifier_secret(expected_nullifier_secret_ciphertext);
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

            // recompute nullifier to pass to server
            let nullifier = user_a.compute_nullifier(nullifier_secret);

            // emit nullifier as user_a
            let code = http_emit_nullifier(
                &context,
                ff_ce_to_le_bytes(&nullifier),
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

    #[cfg(test)]
    mod degree_proof_tests {
        use bincode::Serializer;
        use grapevine_circuits::nova::{degree_proof, verify_grapevine_proof};
        use serde::Serialize;

        use super::*;
        use crate::test_rocket::test_helper::*;

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
        pub async fn test_nonlinear_reordering() {
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
                users.remove(0)
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
            let mut temp_vec = vec![users.remove(8), users.remove(7), users.remove(6), users.remove(2)];
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
            let mut temp_vec = vec![users.remove(12), users.remove(11), users.remove(10), users.remove(2)];
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
            for i in 0..14 {
                // println!("User #{}: {}", i, users[i].username());
            }
            // build proof chain
            let scope_to_find = String::from("user_0");
            for i in 1..14 {
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
            let nullifier = users[4].compute_nullifier(nullifier_secret);
            _ = http_emit_nullifier(
                &context,
                ff_ce_to_le_bytes(&nullifier),
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
                let request = users[i]
                    .new_relationship_request(users[i + 1].username(), &users[i + 1].pubkey());
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
                &ARTIFACTS,
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
            let nullifier = user_0.compute_nullifier(nullifier_secret);
            _ = http_emit_nullifier(
                &context,
                ff_ce_to_le_bytes(&nullifier),
                &mut user_0,
                user_1.username(),
            )
            .await;
            // prove and submit now nullified proof
            let (mut proof, inputs, outputs) = build_degree_inputs(&user_2, &proving_data, 1);
            degree_proof(
                &ARTIFACTS,
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
            let expected_message =
                String::from("{\"ProofFailed\":\"Contains emitted nullifiers\"}");
            assert_eq!(msg, expected_message);
        }
    }

    //     // @TODO: Change eventually because to doesn't need to be mutable?
    //     async fn add_relationship_request(
    //         from: &mut GrapevineAccount,
    //         to: &mut GrapevineAccount,
    //     ) -> (u16, Option<String>) {
    //         let pubkey = to.pubkey();
    //         let encrypted_auth_signature = from.generate_auth_signature(pubkey);

    //         let body = NewRelationshipRequest {
    //             to: to.username().clone(),
    //             ephemeral_key: encrypted_auth_signature.ephemeral_key,
    //             ciphertext: encrypted_auth_signature.ciphertext,
    //         };

    //         let context = GrapevineTestContext::init().await;

    //         let username = from.username().clone();
    //         let signature = generate_nonce_signature(from);

    //         let res = context
    //             .client
    //             .post("/user/relationship/add")
    //             .header(Header::new("X-Authorization", signature))
    //             .header(Header::new("X-Username", username))
    //             .json(&body)
    //             .dispatch()
    //             .await;

    //         let code = res.status().code;
    //         let msg = res.into_string().await;

    //         // Increment nonce after request
    //         let _ = from.increment_nonce(None);

    //         (code, msg)
    //     }

    //     async fn get_account_details_request(user: &mut GrapevineAccount) -> Option<(u64, u64, u64)> {
    //         let context = GrapevineTestContext::init().await;

    //         let username = user.username().clone();
    //         let signature = generate_nonce_signature(user);

    //         let res = context
    //             .client
    //             .get("/user/details")
    //             .header(Header::new("X-Authorization", signature))
    //             .header(Header::new("X-Username", username))
    //             .dispatch()
    //             .await
    //             .into_json::<(u64, u64, u64)>()
    //             .await;

    //         let _ = user.increment_nonce(None);
    //         res
    //     }

    //     async fn get_all_degrees(user: &GrapevineAccount) -> Option<Vec<DegreeData>> {
    //         let context = GrapevineTestContext::init().await;

    //         let username = user.username().clone();
    //         let signature = generate_nonce_signature(user);

    //         context
    //             .client
    //             .get("/user/degrees")
    //             .header(Header::new("X-Authorization", signature))
    //             .header(Header::new("X-Username", username))
    //             .dispatch()
    //             .await
    //             .into_json::<Vec<DegreeData>>()
    //             .await
    //     }

    //     async fn get_available_degrees_request(user: &mut GrapevineAccount) -> Option<Vec<String>> {
    //         let context = GrapevineTestContext::init().await;

    //         let username = user.username().clone();
    //         let signature = generate_nonce_signature(user);

    //         let degrees = context
    //             .client
    //             .get(format!("/proof/available"))
    //             .header(Header::new("X-Authorization", signature))
    //             .header(Header::new("X-Username", username))
    //             .dispatch()
    //             .await
    //             .into_json::<Vec<String>>()
    //             .await;

    //         // Increment nonce after request
    //         let _ = user.increment_nonce(None);
    //         degrees
    //     }

    //     async fn get_phrase_connection_request(
    //         user: &mut GrapevineAccount,
    //         phrase_index: u32,
    //     ) -> Option<(u64, Vec<u64>)> {
    //         let context = GrapevineTestContext::init().await;

    //         let username = user.username().clone();
    //         let signature = generate_nonce_signature(user);

    //         let res = context
    //             .client
    //             .get(format!("/proof/connections/{}", phrase_index))
    //             .header(Header::new("X-Authorization", signature))
    //             .header(Header::new("X-Username", username))
    //             .dispatch()
    //             .await
    //             .into_json::<(u64, Vec<u64>)>()
    //             .await;
    //         let _ = user.increment_nonce(None);
    //         res
    //     }

    //     async fn create_degree_proof_request(
    //         prev_id: &str,
    //         user: &mut GrapevineAccount,
    //     ) -> (u16, Option<String>) {
    //         let public_params = use_public_params().unwrap();
    //         let r1cs = use_r1cs().unwrap();
    //         let wc_path = use_wasm().unwrap();
    //         let context = GrapevineTestContext::init().await;

    //         let username = user.username().clone();
    //         let signature_params = generate_nonce_signature(user);

    //         let preceding = context
    //             .client
    //             .get(format!("/proof/params/{}", prev_id))
    //             .header(Header::new("X-Authorization", signature_params))
    //             .header(Header::new("X-Username", username.clone()))
    //             .dispatch()
    //             .await
    //             .into_json::<ProvingData>()
    //             .await
    //             .unwrap();

    //         // Increment nonce after request
    //         let _ = user.increment_nonce(None);

    //         let auth_signature_encrypted = AuthSignatureEncrypted {
    //             ephemeral_key: preceding.ephemeral_key,
    //             ciphertext: preceding.ciphertext,
    //             username: preceding.username,
    //             recipient: user.pubkey().compress(),
    //         };
    //         let auth_signature = user.decrypt_auth_signature(auth_signature_encrypted);

    //         // decompress proof
    //         let mut proof = decompress_proof(&preceding.proof);
    //         // verify proof
    //         let previous_output =
    //             verify_nova_proof(&proof, &public_params, 1 + (preceding.degree * 2) as usize)
    //                 .unwrap()
    //                 .0;

    //         continue_nova_proof(
    //             &user.pubkey(),
    //             &auth_signature.fmt_circom(),
    //             &mut proof,
    //             previous_output,
    //             wc_path,
    //             &r1cs,
    //             &public_params,
    //         );

    //         let compressed = compress_proof(&proof);

    //         let body = DegreeProofRequest {
    //             proof: compressed,
    //             previous: String::from(prev_id),
    //             degree: preceding.degree + 1,
    //         };
    //         let serialized: Vec<u8> = bincode::serialize(&body).unwrap();

    //         let signature_continue = generate_nonce_signature(user);

    //         let res = context
    //             .client
    //             .post("/proof/degree")
    //             .header(Header::new("X-Authorization", signature_continue))
    //             .header(Header::new("X-Username", username))
    //             .body(serialized)
    //             .dispatch()
    //             .await;

    //         println!("Res: {:?}", res);

    //         let code = res.status().code;
    //         let msg = res.into_string().await;

    //         // Increment nonce after request
    //         user.increment_nonce(None);

    //         (code, msg)
    //     }

    // /**
    //  * Create a new phrase
    //  *
    //  * @param phrase - the phrase being added
    //  * @param description - the description of the phrase
    //  * @param user - the user adding the phrase
    //  * @return
    //  *   - status code
    //  *   - index of the phrase
    //  */
    // async fn phrase_request(
    //     phrase: &String,
    //     description: String,
    //     user: &mut GrapevineAccount,
    // ) -> (u16, String) {
    //     // init context
    //     let context: GrapevineTestContext = GrapevineTestContext::init().await;

    //     // create the phrase proof
    //     let pubkey_vec = vec![user.pubkey().clone()];
    //     let auth_signature_vec = vec![[random_fr(), random_fr(), random_fr()]];

    //     let params = use_public_params().unwrap();
    //     let r1cs = use_r1cs().unwrap();
    //     let wc_path = use_wasm().unwrap();

    //     let proof = nova_proof(
    //         wc_path,
    //         &r1cs,
    //         &params,
    //         &phrase,
    //         &pubkey_vec,
    //         &auth_signature_vec,
    //     )
    //     .unwrap();

    //     // compress proof
    //     let compressed = compress_proof(&proof);
    //     // encrypt phrase
    //     let ciphertext = user.encrypt_phrase(&phrase);

    //     // Mock http request
    //     let body = PhraseRequest {
    //         proof: compressed,
    //         ciphertext,
    //         description,
    //     };
    //     let serialized: Vec<u8> = bincode::serialize(&body).unwrap();
    //     let username = user.username().clone();
    //     let signature = generate_nonce_signature(user);
    //     let res = context
    //         .client
    //         .post("/proof/phrase")
    //         .header(Header::new("X-Authorization", signature))
    //         .header(Header::new("X-Username", username))
    //         .body(serialized)
    //         .dispatch()
    //         .await;

    //     // parse code and msg
    //     let code = res.status().code;
    //     // if successful, can be parsed into u32 index of phrase. Otherwise is error msg
    //     let msg = res.into_string().await.unwrap();

    //     // Increment nonce after request
    //     let _ = user.increment_nonce(None);
    //     (code, msg)
    // }

    //     async fn create_user_request(
    //         context: &GrapevineTestContext,
    //         request: &CreateUserRequest,
    //     ) -> String {
    //         context
    //             .client
    //             .post("/user/create")
    //             .header(ContentType::JSON)
    //             .body(serde_json::json!(request).to_string())
    //             .dispatch()
    //             .await
    //             .into_string()
    //             .await
    //             .unwrap()
    //     }

    //     async fn get_user_request(context: &GrapevineTestContext, username: String) -> Option<User> {
    //         context
    //             .client
    //             .get(format!("/user/{}", username))
    //             .dispatch()
    //             .await
    //             .into_json::<User>()
    //             .await
    //     }

    //     async fn reject_relationship_request(
    //         context: &GrapevineTestContext,
    //         from: &mut GrapevineAccount,
    //         to: &String,
    //     ) -> (u16, Option<String>) {
    //         let username = from.username().clone();
    //         let signature = generate_nonce_signature(from);

    //         let res = context
    //             .client
    //             .post(format!("/user/relationship/reject/{}", to))
    //             .header(Header::new("X-Authorization", signature))
    //             .header(Header::new("X-Username", username))
    //             .dispatch()
    //             .await;

    //         let code = res.status().code;
    //         let msg = res.into_string().await;

    //         // Increment nonce after request
    //         let _ = from.increment_nonce(None);

    //         (code, msg)
    //     }

    // #[rocket::async_test]
    // async fn test_proof_reordering_with_3_proof_chain() {
    //     let context = GrapevineTestContext::init().await;

    //     // Reset db with clean state
    //     GrapevineDB::drop("grapevine_mocked").await;

    //     // Create test users
    //     let mut users = vec![
    //         GrapevineAccount::new(String::from("User_A")),
    //         GrapevineAccount::new(String::from("User_B")),
    //         GrapevineAccount::new(String::from("User_C")),
    //     ];

    //     for i in 0..users.len() {
    //         let request = users[i].create_user_request();
    //         create_user_request(&context, &request).await;
    //     }

    //     // Create phrase a phrase as User A
    //     let phrase = String::from("The sheep waited patiently in the field");
    //     let description = String::from("Sheep have no patience");
    //     _ = phrase_request(&phrase, description, &mut users[0]).await;

    //     // Add relationship between User A and User B, B and C
    //     for i in 0..users.len() - 1 {
    //         // Remove users from vector to reference
    //         let mut preceding = users.remove(i);
    //         // Proceeding is now an index below after removal
    //         let mut proceeding = users.remove(i);
    //         add_relationship_request(&mut preceding, &mut proceeding).await;
    //         add_relationship_request(&mut proceeding, &mut preceding).await;

    //         // Create degree proofs: A <- B <- C
    //         let proofs = get_available_degrees_request(&mut proceeding)
    //             .await
    //             .unwrap();

    //         create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //         // Add users back to vector
    //         users.insert(i, preceding);
    //         users.insert(i + 1, proceeding);
    //     }
    //     println!("8====================================D");

    //     let mut user_a = users.remove(0);
    //     // User C is now an index below after removal
    //     let mut user_c = users.remove(1);

    //     // Establish relationship between A and C now
    //     add_relationship_request(&mut user_a, &mut user_c).await;
    //     add_relationship_request(&mut user_c, &mut user_a).await;

    //     // Check that C now has an available degree request
    //     let proofs_c = get_available_degrees_request(&mut user_c).await.unwrap();

    //     // Create new degree proof between A and C
    //     create_degree_proof_request(&proofs_c[0], &mut user_c).await;
    // }

    //     #[rocket::async_test]
    //     #[ignore]
    //     async fn test_proof_reordering_with_4_proof_chain() {
    //         let context = GrapevineTestContext::init().await;

    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         // Create test users
    //         let mut users = vec![
    //             GrapevineAccount::new(String::from("User_A")),
    //             GrapevineAccount::new(String::from("User_B")),
    //             GrapevineAccount::new(String::from("User_C")),
    //             GrapevineAccount::new(String::from("User_D")),
    //         ];

    //         for i in 0..users.len() {
    //             let request = users[i].create_user_request();
    //             create_user_request(&context, &request).await;
    //         }

    //         // Create phrase a phrase as User A
    //         let phrase = String::from("And that's the waaaayyyy the news goes");
    //         let description = String::from("Wubalubadubdub!");
    //         _ = phrase_request(&phrase, description, &mut users[0]).await;

    //         // Create relationships and degree proofs: A <- B <- C <- D
    //         for i in 0..users.len() - 1 {
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(i);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();
    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             // Add users back to vector
    //             users.insert(i, preceding);
    //             users.insert(i + 1, proceeding);
    //         }

    //         let mut user_a = users.remove(0);
    //         let mut user_c = users.remove(1);
    //         // Establish relationship between A and C now
    //         add_relationship_request(&mut user_a, &mut user_c).await;
    //         add_relationship_request(&mut user_c, &mut user_a).await;

    //         // Check that C now has an available degree request
    //         let proofs_c = get_available_degrees_request(&mut user_c).await.unwrap();
    //         // Create new deree proof between A and C
    //         create_degree_proof_request(&proofs_c[0], &mut user_c).await;

    //         users.insert(0, user_a);
    //         users.insert(2, user_c);

    //         // Check avaiable degree with D and perform necessary update
    //         let proofs_d = get_available_degrees_request(&mut users[3]).await.unwrap();
    //         // Create new degree proof between C and D
    //         create_degree_proof_request(&proofs_d[0], &mut users[3]).await;
    //     }

    //     #[rocket::async_test]
    //     #[ignore]
    //     async fn test_proof_reordering_with_5_proof_chain() {
    //         let context = GrapevineTestContext::init().await;

    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         // Create test users
    //         let mut users = vec![
    //             GrapevineAccount::new(String::from("User_A")),
    //             GrapevineAccount::new(String::from("User_B")),
    //             GrapevineAccount::new(String::from("User_C")),
    //             GrapevineAccount::new(String::from("User_D")),
    //             GrapevineAccount::new(String::from("User_E")),
    //         ];

    //         for i in 0..users.len() {
    //             let request = users[i].create_user_request();
    //             create_user_request(&context, &request).await;
    //         }

    //         // Create phrase a phrase as User A
    //         let phrase = String::from("You are what you eat");
    //         let description = String::from("Mediocre cryptographer");
    //         _ = phrase_request(&phrase, description, &mut users[0]).await;

    //         // Add relationship and degree proofs: A <- B, B <- C
    //         for i in 0..2 {
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(i);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();
    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             // Add users back to vector
    //             users.insert(i, preceding);
    //             users.insert(i + 1, proceeding);
    //         }

    //         // Add relationship and degree proofs: C <- D, C <- E
    //         for i in 0..2 {
    //             let mut preceding = users.remove(2);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i + 2);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();
    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             users.insert(2, preceding);
    //             users.insert(i + 3, proceeding);
    //         }

    //         // Set every proof to degree 2
    //         for i in 0..3 {
    //             let mut preceding = users.remove(0);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i + 1);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();
    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             users.insert(0, preceding);
    //             users.insert(i + 2, proceeding);
    //         }
    //     }

    //     #[rocket::async_test]
    //     #[ignore]
    //     async fn test_proof_reordering_with_27_proof_chain() {
    //         // should this test pass?
    //         // Start with tree structure and eventually have each user connect directly to A
    //         let context = GrapevineTestContext::init().await;

    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let mut users: Vec<GrapevineAccount> = vec![];
    //         // Create test users
    //         for i in 0..27 {
    //             let usersname = format!("User_{}", i);
    //             let user = GrapevineAccount::new(usersname);
    //             let creation_request = user.create_user_request();
    //             create_user_request(&context, &creation_request).await;
    //             users.push(user);
    //         }

    //         // Create phrase a phrase as User A
    //         let phrase =
    //             String::from("They're bureaucrats. I don't respect them. Just keep shooting Morty.");
    //         let description = String::from("It's a figure if speech Morty.");
    //         _ = phrase_request(&phrase, description, &mut users[0]).await;

    //         println!("Started");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         // Create relationships and degree 2 proofs
    //         for i in 0..2 {
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(0);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();

    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;
    //             // Add users back to vector
    //             users.insert(0, preceding);
    //             users.insert(i + 1, proceeding);
    //         }
    //         println!("Degree 2");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         // Create relationships and degree 3 proofs
    //         for i in 0..6 {
    //             let preceding_index = 1 + i / 3;

    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(preceding_index);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i + 2);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();

    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;
    //             // Add users back to vector
    //             users.insert(preceding_index, preceding);
    //             users.insert(i + 2, proceeding);
    //         }
    //         println!("Degree 3");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         // Create relationships and degree 4 proofs
    //         for i in 0..18 {
    //             let preceding_index = 3 + i / 3;
    //             println!("Index: {}", preceding_index);
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(preceding_index);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i + 8);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();

    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             // Add users back to vector
    //             users.insert(preceding_index, preceding);
    //             users.insert(i + 9, proceeding);
    //         }

    //         println!("Degree 4");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         // Bring all proofs to degree 2
    //         for i in 0..24 {
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(0);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i + 2);
    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();

    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             // Add users back to vector
    //             users.insert(0, preceding);
    //             users.insert(i + 3, proceeding);
    //         }
    //         println!("Done");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //         println!("================");
    //     }

    //     #[rocket::async_test]
    //     async fn test_get_degrees_refactor() {
    //         let context = GrapevineTestContext::init().await;

    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         // Create test users
    //         let mut users = vec![
    //             GrapevineAccount::new(String::from("User_A")),
    //             GrapevineAccount::new(String::from("User_B")),
    //             GrapevineAccount::new(String::from("User_C")),
    //             GrapevineAccount::new(String::from("User_D")),
    //         ];

    //         for i in 0..users.len() {
    //             let request = users[i].create_user_request();
    //             create_user_request(&context, &request).await;
    //         }

    //         // Create phrase a phrase as User A
    //         let phrase = String::from("You are what you eat");
    //         let description = String::from("Mediocre cryptographer");
    //         _ = phrase_request(&phrase, description, &mut users[0]).await;

    //         // Add relationship and degree proofs: A <- B, B <- C, C <- D
    //         for i in 0..3 {
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(i);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();
    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             // Add users back to vector
    //             users.insert(i, preceding);
    //             users.insert(i + 1, proceeding);
    //         }

    //         // Get degree proofs for user C
    //         let degrees = get_all_degrees(&users[2]).await;
    //         println!("Degrees: {:?}", degrees);
    //         let degrees = get_all_degrees(&users[1]).await;
    //         println!("Degrees B: {:?}", degrees);
    //         let degrees = get_all_degrees(&users[0]).await;
    //         println!("Degrees A: {:?}", degrees);
    //     }

    //     #[rocket::async_test]
    //     async fn test_inactive_relationships_hidden_in_degree_return() {
    //         let context = GrapevineTestContext::init().await;

    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         // Create test users
    //         let mut users = vec![
    //             GrapevineAccount::new(String::from("User_A")),
    //             GrapevineAccount::new(String::from("User_B")),
    //             GrapevineAccount::new(String::from("User_C")),
    //             GrapevineAccount::new(String::from("User_D")),
    //             GrapevineAccount::new(String::from("User_E")),
    //             GrapevineAccount::new(String::from("User_F")),
    //         ];

    //         for i in 0..users.len() {
    //             let request = users[i].create_user_request();
    //             create_user_request(&context, &request).await;
    //         }

    //         // Create phrase a phrase as User A
    //         let phrase = String::from("The sheep waited patiently in the field");
    //         let description = String::from("Sheep have no patience");
    //         _ = phrase_request(&phrase, description, &mut users[0]).await;

    //         // Add relationship and degree proofs
    //         for i in 0..users.len() - 1 {
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(i);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();
    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             // Add users back to vector
    //             users.insert(i, preceding);
    //             users.insert(i + 1, proceeding);
    //         }

    //         // Link 3 middle users to A
    //         for i in 0..3 {
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(0);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i + 1);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();
    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             // Add users back to vector
    //             users.insert(0, preceding);
    //             users.insert(i + 2, proceeding);
    //         }

    //         // Get degrees
    //         let degrees = get_all_degrees(&mut users[3]).await;
    //         assert_eq!(
    //             degrees.unwrap().len(),
    //             1,
    //             "Inactive degrees should have gotten removed from user's list of degree proofs"
    //         )
    //     }

    //     #[rocket::async_test]
    //     async fn test_create_user_wrong_signature() {
    //         // initiate context
    //         let context = GrapevineTestContext::init().await;
    //         // generate two accounts
    //         let account_1 = GrapevineAccount::new(String::from("userA1"));
    //         let account_2 = GrapevineAccount::new(String::from("userA2"));
    //         // generate a signature from account 2
    //         let bad_sig = account_2.sign_username().compress();
    //         // generate a "Create User" http request from account 1
    //         let mut request = account_1.create_user_request();
    //         // set the signature for creating account 1 to be the signature of account 2
    //         request.signature = bad_sig;

    //         // check response failure
    //         let msg = create_user_request(&context, &request).await;
    //         assert!(
    //             msg.contains("Could not verify user creation signature"),
    //             "Request should fail due to mismatched msg"
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_username_exceeding_character_limit() {
    //         let context = GrapevineTestContext::init().await;

    //         let account = GrapevineAccount::new(String::from("userA1"));

    //         let mut request = account.create_user_request();

    //         let username = "fake_username_1234567890_abcdef";

    //         request.username = username.to_string();

    //         let msg = create_user_request(&context, &request).await;

    //         let condition = msg.contains("UsernameTooLong") && msg.contains(username);

    //         assert!(
    //             condition,
    //             "Username should be marked as exceeding 30 characters"
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_username_with_non_ascii_characters() {
    //         let context = GrapevineTestContext::init().await;

    //         let username = "😍";

    //         let account = GrapevineAccount::new(String::from(username));

    //         let request = account.create_user_request();

    //         let msg = create_user_request(&context, &request).await;

    //         let condition = msg.contains("UsernameNotAscii") && msg.contains(username);

    //         assert!(condition, "User should be created");
    //     }

    //     #[rocket::async_test]
    //     async fn test_successful_user_creation() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let username = String::from("username_successful_creation");

    //         let context = GrapevineTestContext::init().await;

    //         let account = GrapevineAccount::new(username.clone());

    //         let request = account.create_user_request();

    //         assert_eq!(
    //             create_user_request(&context, &request).await,
    //             "User succefully created",
    //             "User should be created"
    //         );

    //         // Check that user was stored in DB
    //         let user = get_user_request(&context, username).await;
    //         assert!(user.is_some(), "User should be stored inside of MongoDB");
    //     }

    //     #[rocket::async_test]
    //     async fn test_duplicate_user() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let username = String::from("username_duplicate_user");

    //         let context = GrapevineTestContext::init().await;

    //         let account = GrapevineAccount::new(username.clone());

    //         let request = account.create_user_request();

    //         create_user_request(&context, &request).await;
    //         let msg = create_user_request(&context, &request).await;

    //         let condition = msg.contains("UserExists") && msg.contains("username_duplicate_user");

    //         assert!(condition, "Users should be enforced to be unique.")
    //     }

    //     #[rocket::async_test]
    //     async fn test_missing_authorization_headers() {
    //         let context = GrapevineTestContext::init().await;

    //         // test without X-Username or X-Authorization header
    //         let res = context.client.get("/user/degrees").dispatch().await;
    //         assert_eq!(res.status(), Status::BadRequest);

    //         // make user
    //         let user = GrapevineAccount::new(String::from("user_missing_auth_header"));
    //         // test without X-Authorization header
    //         let username = user.username().clone();
    //         let username_header = Header::new("X-Username", username);
    //         let res = context
    //             .client
    //             .get("/user/degrees")
    //             .header(username_header)
    //             .dispatch()
    //             .await;
    //         assert_eq!(res.status(), Status::BadRequest);

    //         // test without X-Username header
    //         let signature_header = Header::new("X-Authorization", generate_nonce_signature(&user));
    //         let res = context
    //             .client
    //             .get("/user/degrees")
    //             .header(signature_header)
    //             .dispatch()
    //             .await;
    //         assert_eq!(res.status(), Status::BadRequest);
    //     }

    //     #[rocket::async_test]
    //     #[ignore]
    //     async fn test_invalid_authorization_header() {
    //         let context = GrapevineTestContext::init().await;

    //         let username = String::from("user_invalid_auth_header");

    //         let auth_header = Header::new("X-Authorization", "00000000000");
    //         let username_header = Header::new("X-Username", username);

    //         let res = context
    //             .client
    //             .get("/user/degrees")
    //             .header(auth_header)
    //             .header(username_header)
    //             .dispatch()
    //             .await;
    //         let message = res.into_string().await.unwrap();
    //         println!("Message: {}", message);
    //     }

    //     #[rocket::async_test]
    //     #[ignore]
    //     async fn test_relationship_creation_with_empty_request_body() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let user_a = GrapevineAccount::new(String::from("user_relationship_1_a"));
    //         let user_b = GrapevineAccount::new(String::from("user_relationship_1_b"));

    //         // Create users
    //         let user_a_request = user_a.create_user_request();
    //         let user_b_request = user_b.create_user_request();
    //         create_user_request(&context, &user_a_request).await;
    //         create_user_request(&context, &user_b_request).await;

    //         let signature = user_a.sign_nonce();
    //         let encoded = hex::encode(signature.compress());

    //         let res = context
    //             .client
    //             .post("/user/relationship")
    //             .header(Header::new("X-Authorization", encoded))
    //             .header(Header::new("X-Username", user_a.username().clone()))
    //             .json::<Vec<u8>>(&vec![])
    //             .dispatch()
    //             .await
    //             .into_string()
    //             .await
    //             .unwrap();

    //         println!("Message: {}", res);

    //         assert_eq!(
    //             "User cannot have a relationship with themself", res,
    //             "User should not be able to have a relationsip with themselves."
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_relationship_creation_with_nonexistent_recipient() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut user_a = GrapevineAccount::new(String::from("user_relationship_2_a"));
    //         let mut user_b = GrapevineAccount::new(String::from("user_relationship_2_b"));

    //         // Create user
    //         let user_a_request = user_a.create_user_request();
    //         create_user_request(&context, &user_a_request).await;

    //         let (_, msg) = add_relationship_request(&mut user_a, &mut user_b).await;

    //         assert_eq!(
    //             msg.unwrap(),
    //             "Recipient does not exist.",
    //             "Recipient shouldn't exist"
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_relationship_where_to_is_also_from() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut user_a = GrapevineAccount::new(String::from("user_relationship_3_a"));
    //         let mut clone_a = user_a.clone();

    //         // Create user
    //         let user_a_request = user_a.create_user_request();
    //         create_user_request(&context, &user_a_request).await;

    //         let (_, msg) = add_relationship_request(&mut user_a, &mut clone_a).await;

    //         assert!(
    //             msg.unwrap().contains("RelationshipSenderIsTarget"),
    //             "Relationship cannot be made with your own account"
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_successful_relationship_creation() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut user_a = GrapevineAccount::new(String::from("user_relationship_4_a"));
    //         let mut user_b = GrapevineAccount::new(String::from("user_relationship_4_b"));

    //         // Create user
    //         let user_a_request = user_a.create_user_request();
    //         let user_b_request = user_b.create_user_request();
    //         create_user_request(&context, &user_a_request).await;
    //         create_user_request(&context, &user_b_request).await;

    //         // Check add pending relationship request
    //         let (code, msg) = add_relationship_request(&mut user_a, &mut user_b).await;
    //         assert_eq!(
    //             code,
    //             Status::Created.code,
    //             "Relationship add code should be 201"
    //         );
    //         assert_eq!(
    //             msg.unwrap(),
    //             "Relationship from user_relationship_4_a to user_relationship_4_b pending!",
    //             "Relationship should be pending"
    //         );

    //         // Check activate relationship request
    //         let (code, msg) = add_relationship_request(&mut user_b, &mut user_a).await;
    //         assert_eq!(
    //             code,
    //             Status::Created.code,
    //             "Relationship add code should be 201"
    //         );
    //         assert_eq!(
    //             msg.unwrap(),
    //             "Relationship from user_relationship_4_b to user_relationship_4_a activated!",
    //             "Relationship should be activated"
    //         );

    //         // Check no pending relationships
    //         let pending_relationships = get_relationships_request(&context, &mut user_b, false)
    //             .await
    //             .unwrap();
    //         assert_eq!(
    //             pending_relationships.len(),
    //             0,
    //             "User A should have no pending relationships"
    //         );

    //         // Check a and b have pending requests
    //         let active_relationships = get_relationships_request(&context, &mut user_a, true)
    //             .await
    //             .unwrap();
    //         assert_eq!(
    //             active_relationships.len(),
    //             1,
    //             "User A should have one active relationship"
    //         );
    //         assert_eq!(
    //             active_relationships.get(0).unwrap(),
    //             user_b.username(),
    //             "User B should be active relationship"
    //         );
    //         let active_relationships = get_relationships_request(&context, &mut user_b, true)
    //             .await
    //             .unwrap();
    //         assert_eq!(
    //             active_relationships.len(),
    //             1,
    //             "User B should have one active relationship"
    //         );
    //         assert_eq!(
    //             active_relationships.get(0).unwrap(),
    //             user_a.username(),
    //             "User A should be active relationship"
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_only_prove_with_active_relationship() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut user_a = GrapevineAccount::new(String::from("user_a"));
    //         let mut user_b = GrapevineAccount::new(String::from("user_b"));

    //         // Create user
    //         let user_a_request = user_a.create_user_request();
    //         let user_b_request = user_b.create_user_request();
    //         create_user_request(&context, &user_a_request).await;
    //         create_user_request(&context, &user_b_request).await;

    //         // Add relationship from a to b
    //         _ = add_relationship_request(&mut user_a, &mut user_b).await;

    //         // Create phrase a phrase as User A
    //         let phrase = String::from("The sheep waited patiently in the field");
    //         let description = String::from("Sheep have no patience");
    //         _ = phrase_request(&phrase, description, &mut user_a).await;

    //         // Get available proofs as b and check 0 returned
    //         let proofs = get_available_degrees_request(&mut user_b).await.unwrap();
    //         assert_eq!(proofs.len(), 0, "No proofs should be available");

    //         // Add relationship from b to a
    //         _ = add_relationship_request(&mut user_b, &mut user_a).await;

    //         // Get available proofs as b and check can prove
    //         let proofs = get_available_degrees_request(&mut user_b).await.unwrap();
    //         assert_eq!(proofs.len(), 1, "Proof should be available");
    //         let (code, _) = create_degree_proof_request(&proofs[0], &mut user_b).await;
    //         assert_eq!(code, Status::Created.code, "Proof should be created");
    //     }

    //     #[rocket::async_test]
    //     async fn test_reject_relationship() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;
    //         let context = GrapevineTestContext::init().await;

    //         // create users
    //         let mut user_a = GrapevineAccount::new(String::from("user_a"));
    //         let mut user_b = GrapevineAccount::new(String::from("user_b"));
    //         _ = create_user_request(&context, &user_a.create_user_request()).await;
    //         _ = create_user_request(&context, &user_b.create_user_request()).await;

    //         // send pending relationship request from a to b
    //         _ = add_relationship_request(&mut user_a, &mut user_b).await;
    //         // retrieve pending relationships as b
    //         let pending_relationships = get_relationships_request(&context, &mut user_b, false)
    //             .await
    //             .unwrap();
    //         assert_eq!(
    //             pending_relationships.len(),
    //             1,
    //             "User B should have one pending relationship"
    //         );
    //         assert_eq!(
    //             pending_relationships.get(0).unwrap(),
    //             user_a.username(),
    //             "User A should be pending relationship"
    //         );
    //         // reject relationship from b to a
    //         let (code, _) = reject_relationship_request(&context, &mut user_b, user_a.username()).await;
    //         assert_eq!(code, Status::Ok.code, "Relationship should be rejected");
    //         // show request was removed from pending relationship
    //         let pending_relationships = get_relationships_request(&context, &mut user_b, false)
    //             .await
    //             .unwrap();
    //         assert_eq!(
    //             pending_relationships.len(),
    //             0,
    //             "User B should have one pending relationship"
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_duplicate_pending_relationship() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut user_a = GrapevineAccount::new(String::from("user_relationship_5_a"));
    //         let mut user_b = GrapevineAccount::new(String::from("user_relationship_5_b"));

    //         // Create user
    //         let user_a_request = user_a.create_user_request();
    //         let user_b_request = user_b.create_user_request();
    //         create_user_request(&context, &user_a_request).await;
    //         create_user_request(&context, &user_b_request).await;

    //         add_relationship_request(&mut user_a, &mut user_b).await;

    //         let (code, msg_res) = add_relationship_request(&mut user_a, &mut user_b).await;
    //         assert_eq!(
    //             code,
    //             Status::Conflict.code,
    //             "Relationship should be a conflict"
    //         );
    //         let msg = msg_res.unwrap();
    //         let condition = msg.contains("PendingRelationshipExists")
    //             && msg.contains("user_relationship_5_a")
    //             && msg.contains("user_relationship_5_b");
    //         assert!(condition, "Duplicate pending relationships cannot exist.");
    //     }

    //     #[rocket::async_test]
    //     async fn test_duplicate_active_relationship() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut user_a = GrapevineAccount::new(String::from("user_relationship_5_a"));
    //         let mut user_b = GrapevineAccount::new(String::from("user_relationship_5_b"));

    //         // Create user
    //         let user_a_request = user_a.create_user_request();
    //         let user_b_request = user_b.create_user_request();
    //         create_user_request(&context, &user_a_request).await;
    //         create_user_request(&context, &user_b_request).await;

    //         add_relationship_request(&mut user_a, &mut user_b).await;
    //         add_relationship_request(&mut user_b, &mut user_a).await;

    //         let (code, msg_res) = add_relationship_request(&mut user_a, &mut user_b).await;
    //         assert_eq!(
    //             code,
    //             Status::Conflict.code,
    //             "Relationship should be a conflict"
    //         );
    //         let msg = msg_res.unwrap();
    //         let condition = msg.contains("ActiveRelationshipExists")
    //             && msg.contains("user_relationship_5_a")
    //             && msg.contains("user_relationship_5_b");
    //         assert!(condition, "Duplicate active relationships cannot exist.");
    //     }

    //     #[rocket::async_test]
    //     async fn test_duplicate_phrase() {
    //         // initialize context
    //         GrapevineDB::drop("grapevine_mocked").await;
    //         let context = GrapevineTestContext::init().await;

    //         // add user
    //         let mut user = GrapevineAccount::new(String::from("user"));
    //         create_user_request(&context, &user.create_user_request()).await;

    //         // create & prove phrase
    //         let phrase = String::from("This is a phrase");
    //         let description = String::from("This is a description");
    //         _ = phrase_request(&phrase, description.clone(), &mut user).await;

    //         // attempt to create & prove a duplicate phrase
    //         let (code, msg) = phrase_request(&phrase, description, &mut user).await;
    //         assert!(
    //             msg.contains("DegreeProofExists"),
    //             "Duplicate phrase should be prevented from being added",
    //         );
    //         assert!(
    //             code == Status::Conflict.code,
    //             "Duplicate phrase should return a 409 status code",
    //         )
    //     }

    //     #[rocket::async_test]
    //     async fn test_multiple_degree_1() {
    //         // initialize context
    //         GrapevineDB::drop("grapevine_mocked").await;
    //         let context = GrapevineTestContext::init().await;

    //         // add users
    //         let mut user1 = GrapevineAccount::new(String::from("user1"));
    //         let mut user2 = GrapevineAccount::new(String::from("user2"));
    //         create_user_request(&context, &user1.create_user_request()).await;
    //         create_user_request(&context, &user2.create_user_request()).await;

    //         // create phrase
    //         let phrase = String::from("This is a phrase");
    //         let description = String::from("This is a description");
    //         let (_, res) = phrase_request(&phrase, description.clone(), &mut user1).await;
    //         let data: PhraseCreationResponse = serde_json::from_str(&res).unwrap();

    //         // check that new phrase was created at index 1
    //         assert_eq!(data.phrase_index, 1);
    //         assert_eq!(data.new_phrase, true);

    //         // create phrase
    //         let phrase = String::from("This is a phrase");
    //         let description = String::from("This is a different description");
    //         let (_, res) = phrase_request(&phrase, description.clone(), &mut user2).await;
    //         let data: PhraseCreationResponse = serde_json::from_str(&res).unwrap();

    //         // check that existing phrase was proven at index 1
    //         assert_eq!(data.phrase_index, 1);
    //         assert_eq!(data.new_phrase, false);
    //     }

    //     #[rocket::async_test]
    //     async fn test_create_degree_proof_with_invalid_request_body() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let user = GrapevineAccount::new(String::from("user_degree_proof_1"));
    //         let request = user.create_user_request();

    //         create_user_request(&context, &request).await;

    //         let signature = user.sign_nonce();
    //         let encoded = hex::encode(signature.compress());

    //         let msg = context
    //             .client
    //             .post("/proof/degree")
    //             .header(Header::new("X-Authorization", encoded))
    //             .header(Header::new("X-Username", user.username().clone()))
    //             .body(vec![])
    //             .dispatch()
    //             .await
    //             .into_string()
    //             .await
    //             .unwrap();

    //         let condition = msg.contains("SerdeError") && msg.contains("DegreeProofRequest");
    //         assert!(
    //             condition,
    //             "Degree proof continuation should fail with invalid body"
    //         )
    //     }

    //     #[rocket::async_test]
    //     async fn test_successful_degree_proof_creation() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut user_a = GrapevineAccount::new(String::from("user_degree_proof_2_a"));
    //         let mut user_b = GrapevineAccount::new(String::from("user_degree_proof_2_b"));

    //         // Create users
    //         let user_a_request = user_a.create_user_request();
    //         let user_b_request = user_b.create_user_request();
    //         create_user_request(&context, &user_a_request).await;
    //         create_user_request(&context, &user_b_request).await;

    //         add_relationship_request(&mut user_a, &mut user_b).await;
    //         add_relationship_request(&mut user_b, &mut user_a).await;

    //         // Create phrase a phrase as User A
    //         let phrase = String::from("The first phrase to end them all");
    //         let description = String::from("And on the first day, user_a made a phrase");
    //         _ = phrase_request(&phrase, description, &mut user_a).await;

    //         // prove 2nd degree separation as user b
    //         let proofs = get_available_degrees_request(&mut user_b).await.unwrap();
    //         let (code, _) = create_degree_proof_request(&proofs[0], &mut user_b).await;
    //         assert_eq!(
    //             code,
    //             Status::Created.code,
    //             "Degree proof should have been created"
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_duplicate_degree_proof() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut user_a = GrapevineAccount::new(String::from("user_degree_proof_3_a"));
    //         let mut user_b = GrapevineAccount::new(String::from("user_degree_proof_3_b"));

    //         // Create users
    //         let user_a_request = user_a.create_user_request();
    //         let user_b_request = user_b.create_user_request();
    //         create_user_request(&context, &user_a_request).await;
    //         create_user_request(&context, &user_b_request).await;

    //         add_relationship_request(&mut user_a, &mut user_b).await;
    //         add_relationship_request(&mut user_b, &mut user_a).await;

    //         // Create phrase a phrase as User A
    //         let phrase = String::from("The first phrase to end them all");
    //         let description = String::from("And on the first day, user_a made a phrase");
    //         _ = phrase_request(&phrase, description, &mut user_a).await;

    //         // get proofs as user b
    //         let proofs = get_available_degrees_request(&mut user_b).await.unwrap();

    //         // prove degree 2 separation of phrase as user b
    //         create_degree_proof_request(&proofs[0], &mut user_b).await;

    //         // attempt to prove degree 2 separation of phrase as user b again
    //         let (_, msg) = create_degree_proof_request(&proofs[0], &mut user_b).await;
    //         assert!(
    //             msg.unwrap().contains("DegreeProofExists"),
    //             "Cannot create a second degree proof between same accounts for same phrase"
    //         );
    //     }

    //     #[rocket::async_test]
    //     async fn test_get_account_details() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context: GrapevineTestContext = GrapevineTestContext::init().await;

    //         // Create test users
    //         let mut users = vec![
    //             GrapevineAccount::new(String::from("user_account_details_1")),
    //             GrapevineAccount::new(String::from("user_account_details_2")),
    //             GrapevineAccount::new(String::from("user_account_details_3")),
    //             GrapevineAccount::new(String::from("user_account_details_4")),
    //             GrapevineAccount::new(String::from("user_account_details_5")),
    //             GrapevineAccount::new(String::from("user_account_details_6")),
    //             GrapevineAccount::new(String::from("user_account_details_7")),
    //             GrapevineAccount::new(String::from("user_account_details_8")),
    //             GrapevineAccount::new(String::from("user_account_details_9")),
    //         ];

    //         for i in 0..users.len() {
    //             let request = users[i].create_user_request();
    //             create_user_request(&context, &request).await;
    //         }

    //         let mut user_a = users.remove(0);
    //         let mut user_b = users.remove(0);
    //         let mut user_c = users.remove(0);
    //         let mut user_d = users.remove(0);
    //         let mut user_e = users.remove(0);
    //         let mut user_f = users.remove(0);
    //         let mut user_g = users.remove(0);
    //         let mut user_h = users.remove(0);
    //         let mut user_i = users.remove(0);

    //         let details = get_account_details_request(&mut user_a).await.unwrap();
    //         assert_eq!(details.0, 0, "Phrase count should be 0");
    //         assert_eq!(details.1, 0, "First degree count should be 0");
    //         assert_eq!(details.2, 0, "Second degree count should be 0");

    //         // Create phrase a phrase as User A
    //         let phrase = String::from("The first phrase to end them all");
    //         let description = String::from("And on the first day, user_a made a phrase");
    //         _ = phrase_request(&phrase, description, &mut user_a).await;

    //         let details = get_account_details_request(&mut user_a).await.unwrap();
    //         assert_eq!(details.0, 1, "Phrase count should be 1");
    //         assert_eq!(details.1, 0, "First degree count should be 0");
    //         assert_eq!(details.2, 0, "Second degree count should be 0");

    //         // Add first degree connection and second degree connection
    //         add_relationship_request(&mut user_b, &mut user_a).await;
    //         add_relationship_request(&mut user_a, &mut user_b).await;
    //         add_relationship_request(&mut user_c, &mut user_b).await;
    //         add_relationship_request(&mut user_b, &mut user_c).await;
    //         let details = get_account_details_request(&mut user_a).await.unwrap();
    //         assert_eq!(details.0, 1, "Phrase count should be 1");
    //         assert_eq!(details.1, 1, "First degree count should be 1");
    //         assert_eq!(details.2, 1, "Second degree count should be 1");

    //         // Add more second degree connections
    //         add_relationship_request(&mut user_d, &mut user_b).await;
    //         add_relationship_request(&mut user_b, &mut user_d).await;
    //         add_relationship_request(&mut user_e, &mut user_b).await;
    //         add_relationship_request(&mut user_b, &mut user_e).await;
    //         let details = get_account_details_request(&mut user_a).await.unwrap();
    //         assert_eq!(details.0, 1, "Phrase count should be 1");
    //         assert_eq!(details.1, 1, "First degree count should be 1");
    //         assert_eq!(details.2, 3, "Second degree count should be 3");

    //         // Second degree connections become first degree connections
    //         add_relationship_request(&mut user_d, &mut user_a).await;
    //         add_relationship_request(&mut user_a, &mut user_d).await;
    //         add_relationship_request(&mut user_e, &mut user_a).await;
    //         add_relationship_request(&mut user_a, &mut user_e).await;
    //         let details = get_account_details_request(&mut user_a).await.unwrap();
    //         assert_eq!(details.0, 1, "Phrase count should be 1");
    //         assert_eq!(details.1, 3, "First degree count should be 3");
    //         assert_eq!(details.2, 1, "Second degree count should be 1");

    //         // Test where 3 new degree 2 connections added at once
    //         add_relationship_request(&mut user_f, &mut user_a).await;
    //         add_relationship_request(&mut user_a, &mut user_f).await;
    //         add_relationship_request(&mut user_f, &mut user_g).await;
    //         add_relationship_request(&mut user_g, &mut user_f).await;
    //         add_relationship_request(&mut user_f, &mut user_h).await;
    //         add_relationship_request(&mut user_h, &mut user_f).await;
    //         add_relationship_request(&mut user_f, &mut user_i).await;
    //         add_relationship_request(&mut user_i, &mut user_f).await;
    //         let details = get_account_details_request(&mut user_a).await.unwrap();
    //         assert_eq!(details.0, 1, "Phrase count should be 1");
    //         assert_eq!(details.1, 4, "First degree count should be 3");
    //         assert_eq!(details.2, 4, "Second degree count should be 1");
    //     }

    //     #[rocket::async_test]
    //     async fn test_get_phrase_connections() {
    //         // Reset db with clean state
    //         GrapevineDB::drop("grapevine_mocked").await;

    //         let context = GrapevineTestContext::init().await;

    //         let mut users: Vec<GrapevineAccount> = vec![];

    //         for i in 0..7 {
    //             let user =
    //                 GrapevineAccount::new(String::from(format!("user_account_details_{}", i + 1)));
    //             let request = user.create_user_request();
    //             create_user_request(&context, &request).await;
    //             users.push(user);
    //         }

    //         // create phrase 1
    //         let phrase = String::from("Where there's smoke there's fire");
    //         let description = String::from("5 alarm");
    //         let (_, res) = phrase_request(&phrase, description.clone(), &mut users[0]).await;
    //         let data: PhraseCreationResponse = serde_json::from_str(&res).unwrap();

    //         let connections = get_phrase_connection_request(&mut users[0], data.phrase_index)
    //             .await
    //             .unwrap();
    //         assert_eq!(connections.0, 0);
    //         assert_eq!(connections.1.len(), 0);
    //         // Create degree proofs and relationships
    //         for i in 0..users.len() - 3 {
    //             // Remove users from vector to reference
    //             let mut preceding = users.remove(i);
    //             // Proceeding is now an index below after removal
    //             let mut proceeding = users.remove(i);

    //             add_relationship_request(&mut preceding, &mut proceeding).await;
    //             add_relationship_request(&mut proceeding, &mut preceding).await;

    //             let proofs = get_available_degrees_request(&mut proceeding)
    //                 .await
    //                 .unwrap();
    //             create_degree_proof_request(&proofs[0], &mut proceeding).await;

    //             // Add users back to vector
    //             users.insert(i, preceding);
    //             users.insert(i + 1, proceeding);
    //         }

    //         let mut user_a = users.remove(0);
    //         let mut user_b = users.remove(0);
    //         let mut user_c = users.remove(0);
    //         let mut user_d = users.remove(0);
    //         let mut user_f = users.remove(1);
    //         let mut user_g = users.remove(1);

    //         // user_b <- user_c -> user_d
    //         let connections = get_phrase_connection_request(&mut user_c, data.phrase_index)
    //             .await
    //             .unwrap();
    //         // has 2 total connections
    //         assert_eq!(connections.0, 2);
    //         // not connected to user_a at 1st degree spot
    //         assert_eq!(*connections.1.get(0).unwrap(), 0);
    //         // user_b is is at 2nd degree spot, showing 1 2nd degree connection
    //         assert_eq!(*connections.1.get(1).unwrap(), 1);
    //         // user_c is not connected to themselves and no other 3rd degree connections
    //         assert_eq!(*connections.1.get(2).unwrap(), 0);
    //         // user d is at 4th degree spot, showing 1 4th degree connection
    //         assert_eq!(*connections.1.get(3).unwrap(), 1);
    //         // connection vector is length 4, implying no connections past degree 4
    //         assert_eq!(connections.1.len(), 4);

    //         add_relationship_request(&mut user_a, &mut user_f).await;
    //         add_relationship_request(&mut user_f, &mut user_a).await;

    //         let proofs = get_available_degrees_request(&mut user_f).await.unwrap();
    //         // User F has proof of degree 2
    //         create_degree_proof_request(&proofs[0], &mut user_f).await;
    //         // User G has degree proof 3
    //         add_relationship_request(&mut user_b, &mut user_g).await;
    //         add_relationship_request(&mut user_g, &mut user_b).await;

    //         let proofs = get_available_degrees_request(&mut user_g).await.unwrap();
    //         create_degree_proof_request(&proofs[0], &mut user_g).await;

    //         add_relationship_request(&mut user_c, &mut user_a).await;
    //         add_relationship_request(&mut user_a, &mut user_c).await;
    //         add_relationship_request(&mut user_c, &mut user_d).await;
    //         add_relationship_request(&mut user_d, &mut user_c).await;
    //         add_relationship_request(&mut user_c, &mut user_f).await;
    //         add_relationship_request(&mut user_f, &mut user_c).await;
    //         add_relationship_request(&mut user_c, &mut user_g).await;
    //         add_relationship_request(&mut user_g, &mut user_c).await;

    //         // User C should have:
    //         // * Connection to User A with proof of degree 1
    //         // * Connection to User B with proof of degree 2
    //         // * Connection to User D with proof of degree 4
    //         // * Connection to User F with proof of degree 2
    //         // * Connection to User G with proof of degree 3
    //         let connections = get_phrase_connection_request(&mut user_c, data.phrase_index)
    //             .await
    //             .unwrap();

    //         assert_eq!(connections.0, 5);
    //         assert_eq!(*connections.1.get(0).unwrap(), 1);
    //         assert_eq!(*connections.1.get(1).unwrap(), 2);
    //         assert_eq!(*connections.1.get(2).unwrap(), 1);
    //         assert_eq!(*connections.1.get(3).unwrap(), 1);
    //         assert_eq!(connections.1.len(), 4);

    //         // create phrase 2
    //         let phrase = String::from("Raindrops are falling on my head");
    //         let description = String::from("Get an umbrella ig");
    //         let (_, res) = phrase_request(&phrase, description.clone(), &mut users[0]).await;
    //         let data: PhraseCreationResponse = serde_json::from_str(&res).unwrap();

    //         let connections = get_phrase_connection_request(&mut user_c, data.phrase_index)
    //             .await
    //             .unwrap();

    //         assert_eq!(connections.0, 0);
    //         assert_eq!(connections.1.len(), 0);
    //     }
}
