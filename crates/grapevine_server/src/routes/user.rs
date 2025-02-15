use crate::catchers::{ErrorMessage, GrapevineResponse};
use crate::guards::AuthenticatedUser;
use crate::mongo::GrapevineDB;
use crate::utils::RelationshipStatus;
use babyjubjub_rs::{decompress_point, decompress_signature, verify, Point};
use grapevine_common::compat::{ff_ce_from_le_bytes, ff_ce_to_le_bytes};
use grapevine_common::errors::GrapevineError;
use grapevine_common::http::requests::CreateUserRequest;
use grapevine_common::http::requests::{EmitNullifierRequest, GetNonceRequest};
use grapevine_common::utils::{compute_nullifier, convert_username_to_fr};
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
            return Err(GrapevineResponse::BadRequest(ErrorMessage(Some(
                GrapevineError::SerdeError(String::from("NewRelationshipRequest")),
            ))));
        }
    };

    // ensure from != to
    if &user.0 == &request.to {
        return Err(GrapevineResponse::BadRequest(ErrorMessage(Some(
            GrapevineError::RelationshipSenderIsTarget,
        ))));
    }

    // todo: can combine into one http request
    let sender = db.get_user(&user.0).await.unwrap();
    let recipient = match db.get_user(&request.to).await {
        Some(user) => user,
        None => {
            return Err(GrapevineResponse::NotFound(ErrorMessage(Some(
                GrapevineError::UserNotFound(String::from(request.to)),
            ))));
        }
    };

    // get status of relationship
    let status = match db
        .relationship_status(&recipient.id.unwrap(), &sender.id.unwrap())
        .await
    {
        Ok(status) => status,
        Err(e) => return Err(GrapevineResponse::InternalError(ErrorMessage(Some(e)))),
    };
    // check if relationship is already active
    let mut pending = false;
    if status == RelationshipStatus::Active {
        return Err(GrapevineResponse::Conflict(ErrorMessage(Some(
            GrapevineError::ActiveRelationshipExists(user.0, request.to),
        ))));
    } else {
        pending = status == RelationshipStatus::Pending;
    }

    // create the relationship document from sender to recipient
    let relationship_doc = Relationship {
        id: None,
        sender: Some(sender.id.clone().unwrap()),
        recipient: Some(recipient.id.clone().unwrap()),
        ephemeral_key: Some(request.ephemeral_key),
        signature_ciphertext: Some(request.signature_ciphertext),
        nullifier_ciphertext: Some(request.nullifier_ciphertext),
        nullifier_secret_ciphertext: Some(request.nullifier_secret_ciphertext),
        emitted_nullifier: None,
        active: Some(pending),
    };

    // add relationship doc
    let mut add_error: Option<GrapevineError> = None;
    if let Err(e) = db.add_relationship(&relationship_doc).await {
        add_error = Some(e);
    } else if pending {
        // if pending relationship exists and previous step was successful, activate (todo: transactions)
        if let Err(e) = db
            .activate_relationship(&recipient.id.unwrap(), &sender.id.unwrap())
            .await
        {
            add_error = Some(e);
        }
    };

    // handle outcome
    match add_error {
        Some(err) => Err(GrapevineResponse::InternalError(ErrorMessage(Some(err)))),
        None => {
            let msg = match pending {
                true => "activated",
                false => "pending",
            };
            Ok(GrapevineResponse::Created(format!(
                "Relationship from {} to {} {}!",
                user.0, request.to, msg
            )))
        }
    }
}

/**
 * Gets a list of relationships where the counterparty has nullified their relationship with you
 *
 * @return status:
 *            * 201 if success
 */
#[get("/relationship/nullified")]
pub async fn get_nullified_relationships(
    user: AuthenticatedUser,
    db: &State<GrapevineDB>,
) -> Result<Json<Vec<String>>, GrapevineResponse> {
    match db.get_nullified_relationships(&user.0).await {
        Ok(relationships) => Ok(Json(relationships)),
        Err(e) => Err(GrapevineResponse::InternalError(ErrorMessage(Some(e)))),
    }
}

/**
 * Gets the nullfier secret of a given relationship
 *
 * @param recipient - username of the nullifier recipient in relationship
 *
 * @return status:
 *            * 201 if success
 *            * 401 if relationship is not found   
 *            * 500 if db fails or other unknown issue    
 */
// relationship prefix removed for now due to route collision with get_relationship
#[get("/<recipient>/nullifier-secret")]
pub async fn get_nullifier_secret(
    recipient: String,
    user: AuthenticatedUser,
    db: &State<GrapevineDB>,
) -> Result<Vec<u8>, GrapevineResponse> {
    // TODO: Need to throw error if from is user
    match db.get_relationship(&user.0, &recipient).await {
        // TODO: Solve rocket response error so we can return just encrypted nullifier secret
        Ok(relationship) => Ok(relationship.nullifier_secret_ciphertext.unwrap().to_vec()),
        Err(e) => Err(GrapevineResponse::InternalError(ErrorMessage(Some(e)))),
    }
}

/**
 * Emits a nullifier for a specified relationship, terminating it
 *
 * @param data - the EmitNullifierRequest containing:
 *           * nullifier: nullifier of the sender
 *           * recipient: the username of the recipient
 *
 * @return status:
 *            * 201 if success
 *            * 401 if relationship is not found   
 *            * 500 if db fails or other unknown issue    
 */
#[post("/relationship/nullify", data = "<data>")]
pub async fn emit_nullifier(
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
    // parse the request
    let request = match bincode::deserialize::<EmitNullifierRequest>(&buffer) {
        Ok(req) => req,
        Err(e) => {
            println!(
                "Error deserializing body from binary to EmitNullifierRequest: {:?}",
                e
            );
            return Err(GrapevineResponse::BadRequest(ErrorMessage(Some(
                GrapevineError::SerdeError(String::from("EmitNullifierRequest")),
            ))));
        }
    };

    // fetch address from user
    let address = db.get_user(&user.0).await.unwrap().address.unwrap();
    // compute nullifier from nullifier secret
    let nullifier = compute_nullifier(
        ff_ce_from_le_bytes(address),
        ff_ce_from_le_bytes(request.nullifier_secret),
    );
    let nullifier_bytes = ff_ce_to_le_bytes(&nullifier);

    // store the emitted nullifier and terminate/ nullify the relationship
    if let Err(e) = db
        .nullify_relationship(&nullifier_bytes, &user.0, &request.recipient)
        .await
    {
        return match e {
            GrapevineError::NoRelationship(from, to) => Err(GrapevineResponse::NotFound(
                ErrorMessage(Some(GrapevineError::NoRelationship(from, to))),
            )),
            GrapevineError::RelationshipNullified => {
                Err(GrapevineResponse::Conflict(ErrorMessage(Some(e))))
            }
            _ => Err(GrapevineResponse::InternalError(ErrorMessage(Some(e)))),
        };
    };

    // delete all proofs that contain the given nullifier
    match db.delete_nullified_proofs(&nullifier_bytes).await {
        Ok(_) => Ok(GrapevineResponse::Created(
            "Nullifier emitted successfully".to_string(),
        )),
        Err(e) => Err(GrapevineResponse::InternalError(ErrorMessage(Some(e)))),
    }
}

/**
 * TODO: Remove after tests are written
 * Route used to fetch a relationship while testing
 *
 * @param recipient - recipient username
 * @param sender
 *
 * @return status:
 *            * 201 if success
 *            * 401 if relationship is not found   
 *            * 500 if db fails or other unknown issue    
 */
#[get("/relationship/<recipient>/<sender>")]
pub async fn get_relationship(
    recipient: String,
    sender: String,
    db: &State<GrapevineDB>,
) -> Result<Json<Relationship>, GrapevineResponse> {
    match db.get_relationship(&sender, &recipient).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(GrapevineResponse::InternalError(ErrorMessage(Some(e)))),
    }
}

#[post("/relationship/reject/<username>")]
pub async fn reject_pending_relationship(
    user: AuthenticatedUser,
    username: String,
    db: &State<GrapevineDB>,
) -> Result<Status, GrapevineResponse> {
    // attempt to delete the pending relationship
    println!("Rejecting relationship from {} to {}", username, user.0);
    match db.reject_relationship(&username, &user.0).await {
        Ok(_) => Ok(Status::Ok),
        Err(e) => match e {
            GrapevineError::NoPendingRelationship(from, to) => Err(GrapevineResponse::NotFound(
                ErrorMessage(Some(GrapevineError::NoPendingRelationship(from, to))),
            )),
            _ => Err(GrapevineResponse::InternalError(ErrorMessage(Some(e)))),
        },
    }
}

#[get("/relationship/pending")]
pub async fn get_pending_relationships(
    user: AuthenticatedUser,
    db: &State<GrapevineDB>,
) -> Result<Json<Vec<String>>, GrapevineResponse> {
    match db.get_all_relationship_usernames(&user.0, false).await {
        Ok(relationships) => Ok(Json(relationships)),
        Err(e) => Err(GrapevineResponse::InternalError(ErrorMessage(Some(e)))),
    }
}

#[get("/relationship/active")]
pub async fn get_active_relationships(
    user: AuthenticatedUser,
    db: &State<GrapevineDB>,
) -> Result<Json<Vec<String>>, GrapevineResponse> {
    match db.get_all_relationship_usernames(&user.0, true).await {
        Ok(relationships) => Ok(Json(relationships)),
        Err(e) => Err(GrapevineResponse::InternalError(ErrorMessage(Some(e)))),
    }
}

// /// GET REQUESTS ///

// #[get("/<username>")]
// pub async fn get_user(
//     username: String,
//     db: &State<GrapevineDB>,
// ) -> Result<Json<User>, GrapevineResponse> {
//     match db.get_user(&username).await {
//         Some(user) => Ok(Json(user)),
//         None => Err(GrapevineResponse::NotFound(format!(
//             "User {} does not exist.",
//             username
//         ))),
//     }
// }

/**
 * Return the current nonce of a given users
 *
 * @param request - the nonce request including the username and signature over the nonce for a given user
 * @return - the nonce current nonce of the user
 * @return status:
 *            * 200 if success
 *            * 400 if signature verification error
 *            * 404 if user not found
 */
#[post("/nonce", format = "json", data = "<request>")]
pub async fn get_nonce(
    request: Json<GetNonceRequest>,
    db: &State<GrapevineDB>,
) -> Result<String, GrapevineResponse> {
    // get pubkey & nonce for user
    let (nonce, pubkey) = match db.get_nonce(&request.username).await {
        Some((nonce, pubkey)) => (nonce, pubkey),
        None => {
            return Err(GrapevineResponse::NotFound(ErrorMessage(Some(
                GrapevineError::UserNotFound(request.username.clone()),
            ))))
        }
    };
    // check the validity of the signature over the username
    let message = BigInt::from_bytes_le(Sign::Plus, &request.username.as_bytes());
    let pubkey_decompressed = decompress_point(pubkey).unwrap();

    let signature_decompressed = decompress_signature(&request.signature).unwrap();

    match verify(pubkey_decompressed, signature_decompressed, message) {
        true => (),
        false => {
            return Err(GrapevineResponse::BadRequest(ErrorMessage(Some(
                GrapevineError::Signature(String::from(
                    "Could not verify nonce recovery signature",
                )),
            ))));
        }
    };
    // return the stringified nonce
    Ok(nonce.to_string())
}

/**
 * Return the public key of a given user
 *
 * @param username - the username to look up the public key for
 * @return - the public key of the user
 * @return status:
 *            * 200 if success
 *            * 404 if user not found
 *            * 500 if db fails or other unknown issue
 */
#[get("/<username>/pubkey")]
pub async fn get_pubkey(
    username: String,
    db: &State<GrapevineDB>,
) -> Result<String, GrapevineResponse> {
    match db.get_pubkey(&username).await {
        Some(pubkey) => Ok(hex::encode(pubkey.0)),
        None => Err(GrapevineResponse::NotFound(ErrorMessage(Some(
            GrapevineError::UserNotFound(String::from(username)),
        )))),
    }
}

/**
 * Returns account details related to degree proofs
 *
 * @param username - the username to look up details for
 * @return - count of first degree connections, second degree connections, and phrases created
 * @return status:
 *            * 200 if success
 *            * 404 if user not found
 *            * 500 if db fails or other unknown issue
 */
#[get("/details")]
pub async fn get_account_details(
    user: AuthenticatedUser,
    db: &State<GrapevineDB>,
) -> Result<Json<(u32, u32)>, GrapevineResponse> {
    match db.get_account_details(&user.0).await {
        Some(details) => Ok(Json(details)),
        None => Err(GrapevineResponse::InternalError(ErrorMessage(Some(
            GrapevineError::MongoError(String::from("Error user states")),
        )))),
    }
}

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
