use crate::catchers::ErrorMessage;
use crate::mongo::GrapevineDB;
use crate::utils::PUBLIC_PARAMS;
use crate::{catchers::GrapevineResponse, guards::AuthenticatedUser};
use babyjubjub_rs::decompress_point;
use ff::PrimeField;
use grapevine_circuits::{
    inputs::GrapevineOutputs, nova::verify_grapevine_proof, utils::decompress_proof,
};
use grapevine_common::compat::convert_ff_ce_to_ff;
use grapevine_common::http::responses::ProofMetadata;
use grapevine_common::models::ProvingData;
use grapevine_common::{
    crypto::pubkey_to_address,
    errors::GrapevineError,
    http::requests::{CreateUserRequest, DegreeProofRequest},
    models::{GrapevineProof, User},
    Fr, MAX_USERNAME_CHARS,
};
use mongodb::bson::oid::ObjectId;
use rocket::{
    data::ToByteUnit, http::Status, serde::json::Json, tokio::io::AsyncReadExt, Data, State,
};
use std::str::FromStr;

/// POST REQUESTS ///

/**
 * Creates a new user and authorizes via submission of an identity proof
 */
#[post("/identity", data = "<data>")]
pub async fn prove_identity(
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
    let request = match bincode::deserialize::<CreateUserRequest>(&buffer) {
        Ok(req) => req,
        Err(e) => {
            println!(
                "Error deserializing body from binary to CreateUserRequest: {:?}",
                e
            );
            return Err(GrapevineResponse::BadRequest(ErrorMessage(
                Some(GrapevineError::SerdeError(String::from(
                    "CreateUserRequest",
                ))),
                None,
            )));
        }
    };

    // validate given username
    if request.username.len() > MAX_USERNAME_CHARS {
        return Err(GrapevineResponse::BadRequest(ErrorMessage(
            Some(GrapevineError::UsernameTooLong(request.username.clone())),
            None,
        )));
    };
    if !request.username.is_ascii() {
        return Err(GrapevineResponse::BadRequest(ErrorMessage(
            Some(GrapevineError::UsernameNotAscii(request.username.clone())),
            None,
        )));
    };

    // check if pubkey or username exists
    if let Ok([username_exists, pubkey_exists]) = db
        .check_creation_params(&request.username, &request.pubkey)
        .await
    {
        if username_exists || pubkey_exists {
            let err_msg = match (username_exists, pubkey_exists) {
                (true, true) => Some(GrapevineError::UserExists(request.username.clone())),
                (true, false) => Some(GrapevineError::UsernameExists(request.username.clone())),
                (false, true) => {
                    let pubkey = format!("0x{}", hex::encode(request.pubkey.clone()));
                    Some(GrapevineError::PubkeyExists(pubkey))
                }
                _ => None,
            };
            if err_msg.is_some() {
                return Err(GrapevineResponse::Conflict(ErrorMessage(err_msg, None)));
            }
        }
    } else {
        return Err(GrapevineResponse::InternalError(ErrorMessage(
            Some(GrapevineError::InternalError),
            None,
        )));
    }

    // get the address from the pubkey
    // todo: handle pubkey validation
    let pubkey = decompress_point(request.pubkey.clone()).unwrap();
    let address = convert_ff_ce_to_ff(&pubkey_to_address(&pubkey));
    let address_bytes = address.to_bytes();

    // verify the compressed proof in payload
    let decompressed_proof = decompress_proof(&request.proof);
    let proof_verify_res = verify_grapevine_proof(&decompressed_proof, &*PUBLIC_PARAMS, 0);
    let output = match proof_verify_res {
        Ok(res) => GrapevineOutputs::try_from(res.0).unwrap(),
        Err(e) => {
            println!("Proof verification failed: {:?}", e);
            return Err(GrapevineResponse::BadRequest(ErrorMessage(
                Some(GrapevineError::ProofFailed(String::from(
                    "Given proof is not verifiable",
                ))),
                None,
            )));
        }
    };
    // verify the expected outputs of the proof
    let mut verify_err: Option<String> = None;
    if Fr::zero().ne(&output.degree) {
        verify_err = Some(String::from("Expected degree = 0"));
    } else if *&address.ne(&output.scope) {
        verify_err = Some(format!(
            "Expected identity scope to equal 0x{}",
            hex::encode(&address_bytes)
        ));
    } else if *&address.ne(&output.relation) {
        verify_err = Some(format!(
            "Expected relation to equal 0x{}",
            hex::encode(&address_bytes)
        ));
    }
    if verify_err.is_some() {
        return Err(GrapevineResponse::BadRequest(ErrorMessage(
            Some(GrapevineError::ProofFailed(verify_err.unwrap())),
            None,
        )));
    }

    // create the User document in the db
    let user_doc = User {
        id: None,
        nonce: Some(0),
        username: Some(request.username.clone()),
        pubkey: Some(request.pubkey),
        address: Some(address_bytes),
    };
    let user_oid = match db.create_user(user_doc).await {
        Ok(oid) => oid,
        Err(e) => {
            return Err(GrapevineResponse::InternalError(ErrorMessage(
                Some(e),
                None,
            )))
        }
    };

    // add the proof
    let proof_doc = GrapevineProof {
        id: None,
        scope: Some(user_oid.clone()),
        relation: Some(user_oid.clone()),
        degree: Some(0),
        nullifiers: Some(vec![]),
        proof: Some(request.proof.clone()),
        preceding: None,
        inactive: Some(false),
    };
    match db.add_identity_proof(&user_oid, proof_doc).await {
        Ok(_) => Ok(GrapevineResponse::Created(format!(
            "Created user {}",
            request.username
        ))),
        Err(e) => Err(GrapevineResponse::InternalError(ErrorMessage(
            Some(e),
            None,
        ))),
    }
}

/**
 * Build from a previous degree of connection proof and add it to the database
 *
 * @param data - binary serialized DegreeProofRequest containing:
 *             * username: the username of the user adding a proof of degree of connection
 *             * proof: the gzip-compressed fold proof
 *             * previous: the stringified OID of the previous proof to continue IVC from
 *             * degree: the separation degree of the given proof
 * @return status:
 *             * 201 if successful proof update
 *             * 400 if proof verification failed, deserialization fails, or proof decompression
 *               fails
 *             * 401 if signature mismatch or nonce mismatch
 *             * 404 if user or previous proof not found not found
 *             * 500 if db fails or other unknown issue
 */
#[post("/degree", data = "<data>")]
pub async fn degree_proof(
    user: AuthenticatedUser,
    data: Data<'_>,
    db: &State<GrapevineDB>,
) -> Result<Status, GrapevineResponse> {
    // stream in data
    // todo: implement FromData trait on DegreeProofRequest
    let mut buffer = Vec::new();
    let mut stream = data.open(3.mebibytes()); // Adjust size limit as needed
    if let Err(_) = stream.read_to_end(&mut buffer).await {
        return Err(GrapevineResponse::TooLarge(
            "Request body execeeds 3 MiB".to_string(),
        ));
    }
    let request = match bincode::deserialize::<DegreeProofRequest>(&buffer) {
        Ok(req) => req,
        Err(_) => {
            return Err(GrapevineResponse::BadRequest(ErrorMessage(
                Some(GrapevineError::SerdeError(String::from(
                    "DegreeProofRequest",
                ))),
                None,
            )))
        }
    };

    // verify the proof
    let decompressed_proof = decompress_proof(&request.proof);

    let proof_verify_res = verify_grapevine_proof(
        &decompressed_proof,
        &*PUBLIC_PARAMS,
        request.degree as usize,
    );
    let output = match proof_verify_res {
        Ok(res) => GrapevineOutputs::try_from(res.0).unwrap(),
        Err(e) => {
            println!("Proof verification failed: {:?}", e);
            return Err(GrapevineResponse::BadRequest(ErrorMessage(
                Some(GrapevineError::ProofFailed(String::from(
                    "Given proof is not verifiable",
                ))),
                None,
            )));
        }
    };

    // check for nullifiers
    // @notice: technically we could omit this since server would fail to find previous oid on next step
    //          but in the spirit of testing what would eventually exist onchain we include this step
    let nullifiers = output
        .nullifiers
        .iter()
        .map(|nullifier| nullifier.to_bytes())
        .collect::<Vec<[u8; 32]>>();
    match db.contains_emitted_nullifiers(&nullifiers).await {
        Ok(res) => {
            if res {
                return Err(GrapevineResponse::BadRequest(ErrorMessage(
                    Some(GrapevineError::ProofFailed(
                        "Contains emitted nullifiers".into(),
                    )),
                    None,
                )));
            };
        }
        Err(e) => {
            return Err(GrapevineResponse::InternalError(ErrorMessage(
                Some(e),
                None,
            )))
        }
    };
    // match db.contains_emitted_nullifiers()

    // get all degree data needed to authorize this proof
    let previous_proof_oid = ObjectId::from_str(&request.previous).unwrap();
    let validation_data = match db.get_degree_data(&user.0, &previous_proof_oid).await {
        Some(data) => data,
        None => {
            return Err(GrapevineResponse::NotFound(format!(
                "No proof found with oid {}",
                request.previous.clone()
            )));
        }
    };

    // validate prover address
    let mut verify_err: Option<String> = None;
    let prover_address = Fr::from_repr(validation_data.prover_address).unwrap();
    let prev_nullifiers: Vec<Fr> = validation_data
        .nullifiers
        .iter()
        .map(|n| Fr::from_repr(*n).unwrap())
        .collect();
    let scope = Fr::from_repr(validation_data.scope).unwrap();
    let prev_degree = Fr::from(validation_data.degree as u64);
    let new_nullifier = &output.nullifiers[validation_data.degree as usize];
    if prover_address.ne(&output.relation) {
        verify_err = Some(String::from("Relation does not match caller"))
    } else if scope.ne(&output.scope) {
        verify_err = Some(String::from("Scope does not match previous proof"))
    } else if Fr::from(8u64).lt(&output.degree) {
        verify_err = Some(String::from("Degree is greater than 8"))
    } else if prev_degree.add(&Fr::from(1u64)).ne(&output.degree) {
        verify_err = Some(String::from("Expected degree not found"))
    } else if new_nullifier.eq(&Fr::zero()) {
        verify_err = Some(String::from("New nullifier is not set"))
    }
    for i in 0..validation_data.degree as usize {
        if (&prev_nullifiers[i]).ne(&output.nullifiers[i]) {
            verify_err = Some(String::from("Nullifiers do not match"))
        }
    }
    if verify_err.is_some() {
        return Err(GrapevineResponse::BadRequest(ErrorMessage(
            Some(GrapevineError::ProofFailed(verify_err.unwrap())),
            None,
        )));
    }

    // build new proof
    let proof_doc = GrapevineProof {
        id: None,
        scope: Some(validation_data.scope_oid),
        relation: Some(validation_data.prover_oid),
        degree: Some(request.degree),
        nullifiers: Some(output.nullifiers.iter().map(|n| n.to_bytes()).collect()),
        proof: Some(request.proof),
        preceding: Some(previous_proof_oid),
        inactive: Some(false),
    };

    // TODO: Check that existing proof does not already exist in db at same degree and scope
    // Maybe include this check in validation data?

    // add proof to db and update references
    match db.add_degree_proof(&proof_doc).await {
        Ok(_) => Ok(Status::Created),
        Err(e) => {
            println!("Error adding proof: {:?}", e);
            Err(GrapevineResponse::InternalError(ErrorMessage(
                Some(GrapevineError::MongoError(String::from(
                    "Failed to add proof to db",
                ))),
                None,
            )))
        }
    }
}

/// GET REQUESTS ///

/**
 * Return a list of all available (new) degree proofs from existing connections that a user can
 * build from
 *
 * @param username - the username to look up the available proofs for
 * @return - a vector of stringified OIDs of available proofs to use with get_proof_with_params
 *           route (empty if none)
 * @return status:
 *         - 200 if successful retrieval
 *         - 401 if signature mismatch or nonce mismatch
 *         - 404 if user not found
 *         - 500 if db fails or other unknown issue
 */
#[get("/available")]
pub async fn get_available_proofs(
    user: AuthenticatedUser,
    db: &State<GrapevineDB>,
) -> Result<Json<Vec<ProofMetadata>>, Status> {
    Ok(Json(db.find_available_degrees(user.0).await))
}

/**
* Returns a list of degree proofs a user has created
*
* @return - a vector of AvailableProof structs containing:
*             * oid: the ObjectID of the proof to build from
*             * degree: the separation degree of the proof
*             * relation: immediate connection user has generated degree proof from
*             * scope: the identity proof owner
* @return status:
*            * 200 if success
*            * 401 if signature mismatch or nonce mismatch
*            * 500 if db fails or other unknown issue
*/
#[get("/proven")]
pub async fn get_proven_degrees(
    user: AuthenticatedUser,
    db: &State<GrapevineDB>,
) -> Result<(), GrapevineResponse> {
    // Result<Json<Vec<AvailableProofs>>, GrapevineResponse> {
    db.get_proven_degrees(user.0).await;
    // match db.get_all_degrees(user.0).await {
    //     Some(proofs) => Ok(Json(proofs)),
    //     None => Err(GrapevineResponse::InternalError(ErrorMessage(
    //         Some(GrapevineError::MongoError(String::from(
    //             "Error retrieving degrees in db",
    //         ))),
    //         None,
    //     ))),
    // }
    Ok(())
}

/**
 * Allows a user to return their own proof for a given scope
 *
 * @param scope - the username of the scope of the proof chain
 * @returns - the full proof document
 */
#[get("/scope/<scope>")]
pub async fn get_proof_by_scope(
    user: AuthenticatedUser,
    db: &State<GrapevineDB>,
    scope: String,
) -> Result<Json<GrapevineProof>, GrapevineResponse> {
    match db.find_proof_by_scope(&user.0, &scope).await {
        Some(doc) => Ok(Json(doc)),
        None => Err(GrapevineResponse::NotFound(format!(
            "Proof by {} for scope {}",
            &user.0, &scope
        ))),
    }
}

/**
 * Returns all the information needed to construct a proof of degree of separation from a given user
 *
 * @param oid - the ObjectID of the proof to retrieve
 * @param username - the username to retrieve encrypted auth signature for when proving relationship
 * @return - a ProvingData struct containing:
 *         * degree: the separation degree of the returned proof
 *         * proof: the gzip-compressed fold proof
 *         * username: the username of the proof creator
 *         * ephemeral_key: the ephemeral pubkey that can be combined with the requesting user's
 *           private key to derive returned proof creator's auth signature decryption key
 *         * ciphertext: the encrypted auth signature
 * @return status:
 *         - 200 if successful retrieval
 *         - 401 if signature mismatch or nonce mismatch
 *         - 404 if username or proof not found
 *         - 500 if db fails or other unknown issue
 */
#[get("/params/<oid>")]
pub async fn get_proof_with_params(
    user: AuthenticatedUser,
    oid: String,
    db: &State<GrapevineDB>,
) -> Result<Json<ProvingData>, GrapevineResponse> {
    let oid = ObjectId::from_str(&oid).unwrap();
    match db.get_proof_and_data(user.0, oid).await {
        Some(data) => Ok(Json(data)),
        None => Err(GrapevineResponse::NotFound(format!(
            "No proof found with oid {}",
            oid
        ))),
    }
}
