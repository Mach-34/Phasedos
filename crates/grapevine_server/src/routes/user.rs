use crate::catchers::{ErrorMessage, GrapevineResponse};
use crate::guards::AuthenticatedUser;
use crate::mongo::GrapevineDB;
use babyjubjub_rs::{decompress_point, decompress_signature, verify};
use grapevine_common::errors::GrapevineError;
use grapevine_common::http::requests::{EmitNullifierRequest, GetNonceRequest};
use grapevine_common::http::{requests::CreateUserRequest, responses::DegreeData};
use grapevine_common::utils::convert_username_to_fr;
use grapevine_common::MAX_USERNAME_CHARS;
use grapevine_common::{
    http::requests::NewRelationshipRequest,
    models::{Relationship, User},
};
use rocket::{data::ToByteUnit, tokio::io::AsyncReadExt, Data, State};

use num_bigint::{BigInt, Sign};
use rocket::http::Status;
use rocket::serde::json::Json;

/// POST REQUESTS ///

// /**
//  * Create a new user of the grapevine service
//  *
//  * @param data - the CreateUserRequest containing:
//  *             * username: the username for the new user
//  *             * pubkey: the public key used to authZ/authN and deriving AES encryption keys
//  *             * signature: the signature over the username by pubkey
//  * @return status:
//  *             * 201 if success
//  *             * 400 if username length exceeds 30 characters, username is not valid ASCII,
//  *               invalid signature over username by pubkey, or issues deserializing request
//  *             * 409 if username || pubkey are already in use by another user
//  *             * 500 if db fails or other unknown issue
//  */
// #[post("/create", format = "json", data = "<request>")]
// pub async fn create_user(
//     request: Json<CreateUserRequest>,
//     db: &State<GrapevineDB>,
// ) -> Result<GrapevineResponse, GrapevineResponse> {
//     // check username length is valid
//     if request.username.len() > MAX_USERNAME_CHARS {
//         return Err(GrapevineResponse::BadRequest(ErrorMessage(
//             Some(GrapevineError::UsernameTooLong(request.username.clone())),
//             None,
//         )));
//     };
//     // check request is ascii
//     if !request.username.is_ascii() {
//         return Err(GrapevineResponse::BadRequest(ErrorMessage(
//             Some(GrapevineError::UsernameNotAscii(request.username.clone())),
//             None,
//         )));
//     };
//     // check the validity of the signature over the username
//     let message = BigInt::from_bytes_le(
//         Sign::Plus,
//         &convert_username_to_fr(&request.username).unwrap()[..],
//     );
//     let pubkey_decompressed = decompress_point(request.pubkey).unwrap();
//     let signature_decompressed = decompress_signature(&request.signature).unwrap();
//     match verify(pubkey_decompressed, signature_decompressed, message) {
//         true => (),
//         false => {
//             return Err(GrapevineResponse::BadRequest(ErrorMessage(
//                 Some(GrapevineError::Signature(String::from(
//                     "Could not verify user creation signature",
//                 ))),
//                 None,
//             )));
//         }
//     };
//     // check that the username or pubkey are not already used
//     match db
//         .check_creation_params(&request.username, &request.pubkey)
//         .await
//     {
//         Ok(found) => match found {
//             [true, true] => {
//                 return Err(GrapevineResponse::Conflict(ErrorMessage(
//                     Some(GrapevineError::UserExists(request.username.clone())),
//                     None,
//                 )));
//             }
//             [true, false] => {
//                 return Err(GrapevineResponse::Conflict(ErrorMessage(
//                     Some(GrapevineError::UsernameExists(request.username.clone())),
//                     None,
//                 )));
//             }
//             [false, true] => {
//                 return Err(GrapevineResponse::Conflict(ErrorMessage(
//                     Some(GrapevineError::PubkeyExists(format!(
//                         "0x{}",
//                         hex::encode(request.pubkey.clone())
//                     ))),
//                     None,
//                 )));
//             }
//             _ => (),
//         },
//         Err(e) => {
//             return Err(GrapevineResponse::InternalError(ErrorMessage(
//                 Some(e),
//                 None,
//             )))
//         }
//     };
//     // create the new user in the database
//     let user = User {
//         id: None,
//         nonce: Some(0),
//         username: Some(request.username.clone()),
//         pubkey: Some(request.pubkey.clone()),
//         relationships: Some(vec![]),
//         degree_proofs: Some(vec![]),
//     };
//     match db.create_user(user).await {
//         Ok(_) => Ok(GrapevineResponse::Created(
//             "User succefully created".to_string(),
//         )),
//         Err(e) => Err(GrapevineResponse::InternalError(ErrorMessage(
//             Some(e),
//             None,
//         ))),
//     }
// }

/**
 * Add a unidirectional relationship allowing the target to prove connection to the sender
 * @notice: it would be nice to have a proof of correct encryption for the ciphertext
 *
 * @param data - the NewRelationshipRequest containing:
 *             * from: the username of the sender
 *             * to: the username of the recipient
 *             * ephemeral_key: the ephemeral pubkey that target can combine with their private
 *               key to derive AES key needed to decrypt auth signature
 *             * ciphertext: the encrypted auth signature
 * @return status:
 *            * 201 if success
 *            * 400 if from == to or issues deserializing request
 *            * 401 if signanture or nonce mismatch for sender
 *            * 404 if from or to user does not exist
 *            * 409 if relationship already exists
 */
#[post("/relationship/add", data = "<data>")]
pub async fn add_relationship(
    user: AuthenticatedUser,
    data: Data<'_>,
    db: &State<GrapevineDB>,
) -> Result<GrapevineResponse, GrapevineResponse> {
    // stream in data
    let mut buffer = Vec::new();
    let mut stream = data.open(2.mebibytes()); // Adjust size limit as needed
    if let Err(e) = stream.read_to_end(&mut buffer).await {
        println!("Error reading request body: {:?}", e);
        return Err(GrapevineResponse::TooLarge(
            "Request body execeeds 2 MiB".to_string(),
        ));
    }
    let request = match bincode::deserialize::<NewRelationshipRequest>(&buffer) {
        Ok(req) => req,
        Err(e) => {
            println!(
                "Error deserializing body from binary to NewRelationshipRequest: {:?}",
                e
            );
            return Err(GrapevineResponse::BadRequest(ErrorMessage(
                Some(GrapevineError::SerdeError(String::from(
                    "NewRelationshipRequest",
                ))),
                None,
            )));
        }
    };

    // ensure from != to
    if &user.0 == &request.to {
        return Err(GrapevineResponse::BadRequest(ErrorMessage(
            Some(GrapevineError::RelationshipSenderIsTarget),
            None,
        )));
    }

    // todo: can combine into one http request
    let sender = db.get_user(&user.0).await.unwrap();
    let recipient = match db.get_user(&request.to).await {
        Some(user) => user,
        None => {
            return Err(GrapevineResponse::NotFound(String::from(
                "Recipient does not exist.".to_string(),
            )));
        }
    };

    // TODO: Commenting this out for now so we are not blocked
    // ensure relationship does not alreaday exist between two users
    // match db
    //     .check_relationship_exists(&sender.id.unwrap(), &recipient.id.unwrap())
    //     .await
    // {
    //     Ok((exists, active)) => match exists {
    //         true => {
    //             let err = match active {
    //                 true => GrapevineError::ActiveRelationshipExists(user.0, request.to.clone()),
    //                 false => GrapevineError::PendingRelationshipExists(user.0, request.to.clone()),
    //             };
    //             return Err(GrapevineResponse::Conflict(ErrorMessage(Some(err), None)));
    //         }
    //         false => (),
    //     },
    //     Err(e) => {
    //         return Err(GrapevineResponse::InternalError(ErrorMessage(
    //             Some(e),
    //             None,
    //         )))
    //     }
    // }

    // check if a pending relationship from recipient to sender exists
    let activate = match db
        .find_pending_relationship(&recipient.id.unwrap(), &sender.id.unwrap())
        .await
    {
        Ok(exists) => exists,
        Err(e) => {
            return Err(GrapevineResponse::InternalError(ErrorMessage(
                Some(e),
                None,
            )))
        }
    };

    let from_relationship_doc = Relationship {
        id: None,
        sender: Some(sender.id.unwrap()),
        recipient: Some(recipient.id.unwrap()),
        encrypted_nullifier_secret: Some(request.encrypted_nullifier_secret),
        encrypted_nullifier: None,
        ephemeral_key: None,
        encrypted_auth_signature: None,
        active: Some(activate),
    };

    let to_relationship_doc = Relationship {
        id: None,
        sender: Some(recipient.id.unwrap()),
        recipient: Some(sender.id.unwrap()),
        encrypted_nullifier_secret: None,
        ephemeral_key: Some(request.ephemeral_key),
        encrypted_auth_signature: Some(request.encrypted_auth_signature),
        encrypted_nullifier: Some(request.encrypted_nullifier),
        active: Some(activate),
    };

    let req = match activate {
        true => {
            db.activate_relationship(&from_relationship_doc, &to_relationship_doc)
                .await
        }
        false => {
            // TODO: Can prolly just achieve this with an "add_pending_relationships" function
            db.add_pending_relationship(&from_relationship_doc).await;
            db.add_pending_relationship(&to_relationship_doc).await;
            Ok(())
        }
    };

    match req {
        Ok(_) => {
            let msg = match activate {
                true => "activated",
                false => "pending",
            };
            Ok(GrapevineResponse::Created(format!(
                "Relationship from {} to {} {}!",
                user.0, request.to, msg
            )))
        }
        Err(_) => Err(GrapevineResponse::InternalError(ErrorMessage(
            Some(GrapevineError::MongoError(String::from(
                "Failed to add relationship to db",
            ))),
            None,
        ))),
    }
}

#[get("/relationship/nullifier-secret/<recipient>")]
pub async fn get_nullifier_secret(
    recipient: String,
    user: AuthenticatedUser,
    db: &State<GrapevineDB>,
) -> Result<Vec<u8>, GrapevineResponse> {
    // TODO: Need to throw error if from is user
    match db.get_relationship(&user.0, &recipient).await {
        // TODO: Solve rocket response error so we can return just encrypted nullifier secret
        Ok(relationship) => Ok(relationship.encrypted_nullifier_secret.unwrap().to_vec()),
        Err(e) => Err(GrapevineResponse::InternalError(ErrorMessage(
            Some(e),
            None,
        ))),
    }
}

#[post("/relationship/emit-nullifier", data = "<data>")]
pub async fn emit_nullifier(
    user: AuthenticatedUser,
    data: Data<'_>,
    db: &State<GrapevineDB>,
) -> Result<(), GrapevineResponse> {
    // stream in data
    let mut buffer = Vec::new();
    let mut stream = data.open(2.mebibytes()); // Adjust size limit as needed
    if let Err(e) = stream.read_to_end(&mut buffer).await {
        println!("Error reading request body: {:?}", e);
        return Err(GrapevineResponse::TooLarge(
            "Request body execeeds 2 MiB".to_string(),
        ));
    }
    let request = match bincode::deserialize::<EmitNullifierRequest>(&buffer) {
        Ok(req) => req,
        Err(e) => {
            println!(
                "Error deserializing body from binary to EmitNullifierRequest: {:?}",
                e
            );
            return Err(GrapevineResponse::BadRequest(ErrorMessage(
                Some(GrapevineError::SerdeError(String::from(
                    "EmitNullifierRequest",
                ))),
                None,
            )));
        }
    };

    match db
        .terminate_relationship(request.nullifier, &user.0, &request.recipient)
        .await
    {
        Ok(_) => Ok(()),
        Err(e) => Err(GrapevineResponse::InternalError(ErrorMessage(
            Some(e),
            None,
        ))),
    }
}

// #[post("/relationship/reject/<username>")]
// pub async fn reject_pending_relationship(
//     user: AuthenticatedUser,
//     username: String,
//     db: &State<GrapevineDB>,
// ) -> Result<Status, GrapevineResponse> {
//     // attempt to delete the pending relationship
//     println!("Rejecting relationship from {} to {}", username, user.0);
//     match db.reject_relationship(&username, &user.0).await {
//         Ok(_) => Ok(Status::Ok),
//         Err(e) => match e {
//             GrapevineError::NoPendingRelationship(from, to) => Err(GrapevineResponse::NotFound(
//                 format!("No pending relationship exists from {} to {}", from, to),
//             )),
//             _ => Err(GrapevineResponse::InternalError(ErrorMessage(
//                 Some(e),
//                 None,
//             ))),
//         },
//     }
// }

// #[get("/relationship/pending")]
// pub async fn get_pending_relationships(
//     user: AuthenticatedUser,
//     db: &State<GrapevineDB>,
// ) -> Result<Json<Vec<String>>, GrapevineResponse> {
//     match db.get_relationships(&user.0, false).await {
//         Ok(relationships) => Ok(Json(relationships)),
//         Err(e) => Err(GrapevineResponse::InternalError(ErrorMessage(
//             Some(e),
//             None,
//         ))),
//     }
// }

#[get("/relationship/active")]
pub async fn get_active_relationships(
    user: AuthenticatedUser,
    db: &State<GrapevineDB>,
) -> Result<Json<Vec<String>>, GrapevineResponse> {
    match db.get_relationships(&user.0, true).await {
        Ok(relationships) => Ok(Json(relationships)),
        Err(e) => Err(GrapevineResponse::InternalError(ErrorMessage(
            Some(e),
            None,
        ))),
    }
}

// /// GET REQUESTS ///

// /**
//  * @todo: remove / replace with get nonce
//  */
// // #[get("/<username>")]
// // pub async fn get_user(
// //     username: String,
// //     db: &State<GrapevineDB>,
// // ) -> Result<Json<User>, GrapevineResponse> {
// //     match db.get_user(&username).await {
// //         Some(user) => Ok(Json(user)),
// //         None => Err(GrapevineResponse::NotFound(format!(
// //             "User {} does not exist.",
// //             username
// //         ))),
// //     }
// // }

// // #[post("/nonce", format = "json", data = "<request>")]
// // pub async fn get_nonce(
// //     request: Json<GetNonceRequest>,
// //     db: &State<GrapevineDB>,
// // ) -> Result<String, GrapevineResponse> {
// //     // get pubkey & nonce for user
// //     let (nonce, pubkey) = match db.get_nonce(&request.username).await {
// //         Some((nonce, pubkey)) => (nonce, pubkey),
// //         None => {
// //             return Err(GrapevineResponse::NotFound(String::from(
// //                 "User not does not exist.",
// //             )))
// //         }
// //     };
// //     // check the validity of the signature over the username
// //     let message = BigInt::from_bytes_le(
// //         Sign::Plus,
// //         &convert_username_to_fr(&request.username).unwrap()[..],
// //     );
// //     let pubkey_decompressed = decompress_point(pubkey).unwrap();
// //     let signature_decompressed = decompress_signature(&request.signature).unwrap();
// //     match verify(pubkey_decompressed, signature_decompressed, message) {
// //         true => (),
// //         false => {
// //             return Err(GrapevineResponse::BadRequest(ErrorMessage(
// //                 Some(GrapevineError::Signature(String::from(
// //                     "Could not verify nonce recovery signature",
// //                 ))),
// //                 None,
// //             )));
// //         }
// //     };
// //     // return the stringified nonce
// //     Ok(nonce.to_string())
// // }

// // /**
// //  * Return the public key of a given user
// //  *
// //  * @param username - the username to look up the public key for
// //  * @return - the public key of the user
// //  * @return status:
// //  *            * 200 if success
// //  *            * 404 if user not found
// //  *            * 500 if db fails or other unknown issue
// //  */
// // #[get("/<username>/pubkey")]
// // pub async fn get_pubkey(
// //     username: String,
// //     db: &State<GrapevineDB>,
// // ) -> Result<String, GrapevineResponse> {
// //     match db.get_pubkey(username).await {
// //         Some(pubkey) => Ok(hex::encode(pubkey)),
// //         None => Err(GrapevineResponse::NotFound(String::from(
// //             "User not does not exist.",
// //         ))),
// //     }
// // }

// // /**
// //  * Return a list of all available (new) degree proofs from existing connections that a user can
// //  * build from (empty if none)
// //  *
// //  * @param username - the username to look up the available proofs for
// //  * @return - a vector of DegreeData structs containing:
// //  *             * oid: the ObjectID of the proof to build from
// //  *             * relation: the separation degree of the proof
// //  *             * phrase_hash: the poseidon hash of the original phrase at the start of the chain
// //  * @return status:
// //  *            * 200 if success
// //  *            * 401 if signature mismatch or nonce mismatch
// //  *            * 404 if user not found
// //  *            * 500 if db fails or other unknown issue
// //  */
// // #[get("/degrees")]
// // pub async fn get_all_degrees(
// //     user: AuthenticatedUser,
// //     db: &State<GrapevineDB>,
// // ) -> Result<Json<Vec<DegreeData>>, GrapevineResponse> {
// //     match db.get_all_degrees(user.0).await {
// //         Some(proofs) => Ok(Json(proofs)),
// //         None => Err(GrapevineResponse::InternalError(ErrorMessage(
// //             Some(GrapevineError::MongoError(String::from(
// //                 "Error retrieving degrees in db",
// //             ))),
// //             None,
// //         ))),
// //     }
// // }

// // /**
// //  * Returns account details related to degree proofs
// //  *
// //  * @param username - the username to look up details for
// //  * @return - count of first degree connections, second degree connections, and phrases created
// //  * @return status:
// //  *            * 200 if success
// //  *            * 404 if user not found
// //  *            * 500 if db fails or other unknown issue
// //  */
// // #[get("/details")]
// // pub async fn get_account_details(
// //     user: AuthenticatedUser,
// //     db: &State<GrapevineDB>,
// // ) -> Result<Json<(u64, u64, u64)>, GrapevineResponse> {
// //     let recipient = match db.get_user(&user.0).await {
// //         Some(user) => user,
// //         None => {
// //             return Err(GrapevineResponse::NotFound(String::from(
// //                 "Recipient does not exist.".to_string(),
// //             )));
// //         }
// //     };
// //     match db.get_account_details(&recipient.id.unwrap()).await {
// //         Some(details) => Ok(Json(details)),
// //         None => Err(GrapevineResponse::InternalError(ErrorMessage(
// //             Some(GrapevineError::MongoError(String::from(
// //                 "Error user states",
// //             ))),
// //             None,
// //         ))),
// //     }
// // }

// // /**
// //  * Return a list of the usernames of all direct connections by a given user
// //  *
// //  * @param username - the username to look up relationships for
// //  * @return - a vector of stringified usernames of direct connections (empty if none found)
// //  * @return status:
// //  *            * 200 if success
// //  *            * 401 if signature mismatch or nonce mismatch for requested user
// //  *            * 404 if user not found
// //  *            * 500 if db fails or other unknown issue
// //  */
// // pub async fn get_relationships(
// //     username: String,
// //     db: &State<GrapevineDB>,
// // ) -> Result<Json<Vec<String>>, Status> {
// //     todo!("implement get_relationships")
// // }
