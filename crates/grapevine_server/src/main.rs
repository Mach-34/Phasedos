#[macro_use]
extern crate rocket;
use catchers::{bad_request, not_found, unauthorized};
use lazy_static::lazy_static;
use mongo::GrapevineDB;
use mongodb::bson::doc;
use rocket::fs::{relative, FileServer};

mod catchers;
mod guards;
mod mongo;
mod routes;
mod utils;

#[cfg(test)]
mod tests {
    mod auth;
    mod helpers;
    mod http;
    mod proof;
    mod user;
}

lazy_static! {
    static ref MONGODB_URI: String = String::from(env!("MONGODB_URI"));
    static ref DATABASE_NAME: String = String::from(env!("DATABASE_NAME"));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // connect to mongodb
    let mongo = GrapevineDB::init(&*&DATABASE_NAME, &*&MONGODB_URI).await;
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
        .register("/", catchers![bad_request, not_found, unauthorized])
        .launch()
        .await?;
    Ok(())
}

#[get("/health")]
pub async fn health() -> &'static str {
    "Hello, world!"
}

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
