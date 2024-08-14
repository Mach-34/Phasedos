use crate::http::{
    add_relationship_req, create_user_req, degree_proof_req, emit_nullifier,
    get_account_details_req, get_available_proofs_req, get_degree_by_scope_req, get_nonce_req,
    get_nullifier_secret, get_proof_with_params_req, get_proven_degrees_req, get_pubkey_req,
    get_relationships_req, reject_relationship_req,
};
use crate::utils::artifacts_guard;
use crate::utils::fs::{use_public_params, use_r1cs, use_wasm, ACCOUNT_PATH};
use babyjubjub_rs::{decompress_point, decompress_signature};
use ff::PrimeField;
use grapevine_circuits::inputs::{GrapevineArtifacts, GrapevineInputs, GrapevineOutputs};
use grapevine_circuits::nova::{degree_proof, identity_proof, verify_grapevine_proof};
// use grapevine_circuits::nova::{continue_nova_proof, nova_proof, verify_nova_proof};
use grapevine_circuits::utils::{compress_proof, decompress_proof};
use grapevine_common::account::GrapevineAccount;
use grapevine_common::auth_secret::AuthSecretEncrypted;
use grapevine_common::compat::{ff_ce_from_le_bytes, ff_ce_to_le_bytes};
use grapevine_common::errors::GrapevineError;
use grapevine_common::http::requests::{DegreeProofRequest, EmitNullifierRequest};
use grapevine_common::utils::{random_fr, to_array_32};
use grapevine_common::Fr;
use nova_scotia::{continue_recursive_circuit, FileLocation};

use std::path::Path;

/**
 * Get the details of the current account
 */
pub async fn account_details() -> Result<String, GrapevineError> {
    // get account
    let mut account = match get_account() {
        Ok(account) => account,
        Err(e) => return Err(e),
    };
    // sync nonce
    synchronize_nonce().await?;
    let pubkey = hex::encode(account.pubkey().compress());

    // Fetch account stats
    let res = get_account_details_req(&mut account).await;

    match res {
        Ok(_) => {
            let details = res.unwrap();
            Ok(format!(
                "Username: {}\nPublic key: 0x{}\n# 1st degree connections: {}\n# 2nd degree connections: {}\n# phrases created: {}",
                account.username(),
                pubkey,
                details.1,
                details.2,
                details.0
            ))
        }
        Err(e) => Err(e),
    }
}

/**
 * Export the private key of the current account
 */
pub fn export_key() -> Result<String, GrapevineError> {
    // get account
    let account = match get_account() {
        Ok(account) => account,
        Err(e) => return Err(e),
    };
    // Get private key
    let pk = hex::encode(account.private_key_raw());
    Ok(format!(
        "Sensitive account details for {}:\nPrivate Key: 0x{}",
        account.username(),
        pk,
    ))
}

/**
 * Register a new user on Grapevine
 *
 * @param username - the username to register
 */
pub async fn register(username: &String) -> Result<String, GrapevineError> {
    // check username is < 30 chars
    if username.len() > 30 {
        return Err(GrapevineError::UsernameTooLong(username.clone()));
    }
    // check username is ascii
    if !username.is_ascii() {
        return Err(GrapevineError::UsernameNotAscii(username.clone()));
    }
    // make account (or retrieve from fs)
    let account = make_or_get_account(username.clone())?;
    // generate identity proof
    let private_key = account.private_key();
    let identity_inputs = GrapevineInputs::identity_step(&private_key);

    artifacts_guard().await.unwrap();

    let artifacts = GrapevineArtifacts {
        params: use_public_params().unwrap(),
        r1cs: use_r1cs().unwrap(),
        wasm_location: FileLocation::PathBuf(use_wasm().unwrap()),
    };

    let proof = identity_proof(&artifacts, &identity_inputs).unwrap();
    let compressed = compress_proof(&proof);
    // build request body
    let body = account.create_user_request(compressed);
    // send create user request
    let res = create_user_req(body).await;
    match res {
        Ok(_) => Ok(format!("Success: registered account for \"{}\"", username)),
        Err(e) => Err(e),
    }
}

/**
 * Add a connection to another user by creating an auth signature by signing their pubkey
 *
 * @param username - the username of the user to add a connection to
 */
pub async fn add_relationship(username: &String) -> Result<String, GrapevineError> {
    // get own account
    let mut account = get_account()?;
    // sync nonce
    synchronize_nonce().await?;
    // get pubkey for recipient
    let pubkey = match get_pubkey_req(username.clone()).await {
        Ok(pubkey) => pubkey,
        Err(e) => return Err(e),
    };
    // build relationship request body with encrypted auth signature payload
    let body = account.new_relationship_request(&username, &pubkey);
    // send add relationship request
    let res = add_relationship_req(&mut account, body).await;
    match res {
        Ok(message) => Ok(message),
        Err(e) => Err(e),
    }
}

/**
 * Reject a pending relationship request
 *
 * @param username - the username of the user to reject the relationship with
 */
pub async fn reject_relationship(username: &String) -> Result<String, GrapevineError> {
    // get account
    let mut account = get_account()?;
    // sync nonce
    synchronize_nonce().await?;
    // send request
    let res = reject_relationship_req(username, &mut account).await;
    match res {
        Ok(_) => Ok(format!(
            "Success: rejected pending relationship with \"{}\"",
            username
        )),
        Err(e) => Err(e),
    }
}

/**
 * Get available degree proofs that an account can prove from
 */
pub async fn get_available_proofs() -> Result<String, GrapevineError> {
    // get account
    let mut account = get_account()?;
    // sync nonce
    synchronize_nonce().await?;

    match get_available_proofs_req(&mut account).await {
        Ok(proofs) => {
            let degree_col_width = 8;
            let relation_col_width = 4;

            // calculate longest scope username
            let scope_col_width = proofs.iter().fold(0, |acc, x| {
                if acc < x.scope.len() {
                    x.scope.len()
                } else {
                    acc
                }
            }) + 8;

            let mut output = String::new();

            let str = format!(
                "{: <degree_col_width$} {: <scope_col_width$} {: <relation_col_width$}\n\n",
                "Degree", "Scope", "Relation"
            );
            output.push_str(&str);
            for proof in proofs {
                output.push_str(&format!(
                    "{: <degree_col_width$} {: <scope_col_width$} {: <relation_col_width$}\n",
                    proof.degree, proof.scope, proof.relation
                ));
            }
            Ok(output)
        }
        Err(e) => Err(e),
    }
}

/**
 * Proves all available degrees with existing relations
 */
pub async fn prove_all_available() -> Result<String, GrapevineError> {
    // GETTING
    // get account
    let mut account = get_account()?;
    // sync nonce
    synchronize_nonce().await?;
    // get available proofs
    let res = get_available_proofs_req(&mut account).await;
    // // handle result
    let proofs = match res {
        Ok(proofs) => {
            if proofs.len() == 0 {
                return Ok(format!(
                    "No new degree proofs found for user \"{}\"",
                    account.username()
                ));
            }
            proofs
        }
        Err(e) => {
            println!("Failed to get available proofs");
            return Err(e);
        }
    };

    // PROVING
    // ensure proving artifacts are downloaded
    artifacts_guard().await.unwrap();

    let artifacts = GrapevineArtifacts {
        params: use_public_params().unwrap(),
        r1cs: use_r1cs().unwrap(),
        wasm_location: FileLocation::PathBuf(use_wasm().unwrap()),
    };

    let proof_count = proofs.len();
    println!(
        "Proving {} new degree{}...",
        proof_count,
        if proof_count == 1 { "" } else { "s" }
    );

    // TODO: FIX ONCE PROVING IS TESTED //

    for i in 0..proof_count {
        let available_proof = proofs[i].clone();
        // get proof and encrypted auth signature
        let res = get_proof_with_params_req(&mut account, available_proof.id.to_string()).await;
        let proving_data = match res {
            Ok(proving_data) => proving_data,
            Err(e) => return Err(e),
        };

        println!("Scope: {}", available_proof.scope);
        println!("Relation: {}", available_proof.relation);
        println!("Degree being proved: {}", available_proof.degree + 1);
        println!("Proving...");

        // prepare inputs
        let auth_secret_encrypted = AuthSecretEncrypted {
            ephemeral_key: proving_data.ephemeral_key,
            nullifier_ciphertext: proving_data.nullifier_ciphertext,
            signature_ciphertext: proving_data.signature_ciphertext,
        };

        let auth_secret = account.decrypt_auth_signature(auth_secret_encrypted);
        let mut proof = decompress_proof(&proving_data.proof);
        let verified = verify_grapevine_proof(
            &proof,
            &artifacts.params,
            (available_proof.degree * 2) as usize,
        );
        let previous_output = match verified {
            Ok(data) => data.0,
            Err(e) => {
                println!("Verification Failed");
                return Err(GrapevineError::ProofFailed(String::from(
                    "Given proof is not verifiable",
                )));
            }
        };

        let auth_signature = decompress_signature(&auth_secret.signature).unwrap();
        let relation_pubkey = decompress_point(proving_data.relation_pubkey).unwrap();
        let nullifier = Fr::from_repr(auth_secret.nullifier).unwrap();

        let inputs = GrapevineInputs::degree_step(
            &account.private_key(),
            &relation_pubkey,
            &nullifier,
            &previous_output[2],
            &auth_signature,
        );

        match degree_proof(&artifacts, &inputs, &mut proof, &previous_output) {
            Ok(_) => (),
            Err(_) => {
                println!("Proof continuation failed");
                return Err(GrapevineError::ProofFailed(String::from(
                    "Given proof is not verifiable",
                )));
            }
        }
        let compressed = compress_proof(&proof);
        // build request body
        let body = DegreeProofRequest {
            proof: compressed,
            previous: available_proof.id.to_string(),
            degree: available_proof.degree + 1,
        };

        // handle response from server
        let res: Result<(), GrapevineError> = degree_proof_req(&mut account, body).await;
        match res {
            Ok(_) => (),
            Err(e) => return Err(e),
        }
        println!(
            "Proved degree {} for scope {}",
            available_proof.degree + 1,
            available_proof.scope
        );
    }
    Ok(format!(
        "Success: proved {} new degree proof{}",
        proof_count,
        if proof_count == 1 { "" } else { "s" }
    ))
}

/**
 * Gets all (pending, active) relationships for the account
 *
 * @param active - whether to get active relationships or pending relationships
 */
pub async fn get_relationships(active: bool) -> Result<String, GrapevineError> {
    // get account
    let mut account = get_account()?;
    // sync nonce
    synchronize_nonce().await?;
    // send request
    let res = get_relationships_req(active, &mut account).await;
    match res {
        Ok(data) => {
            let relation_type = if active { "Active" } else { "Pending" };
            let count = data.len();
            if count == 0 {
                println!("No {} relationships found for this account", relation_type);
                return Ok(String::from(""));
            }
            println!("===============================");
            println!(
                "Showing {} {} {} for {}:",
                count,
                relation_type,
                if count == 1 {
                    "relationship"
                } else {
                    "relationships"
                },
                account.username()
            );
            for relationship in data {
                println!("|=> \"{}\"", relationship);
            }
            Ok(String::from(""))
        }
        Err(e) => Err(e),
    }
}

/**
 * Emits the nullifier for a specified relationship, terminating it
 *
 * @param recipient - username of nullifier recipient in relationship
 */
pub async fn nullify_relationship(recipient: &String) -> Result<String, GrapevineError> {
    // get account
    let mut account = get_account()?;
    // sync nonce
    synchronize_nonce().await?;

    let encrypted_nullifier_secret = get_nullifier_secret(&mut account, recipient).await.unwrap();
    let bytes: [u8; 48] = encrypted_nullifier_secret.try_into().unwrap();
    let nullifier_secret = account.decrypt_nullifier_secret(bytes);

    let request_body = EmitNullifierRequest {
        nullifier_secret: ff_ce_to_le_bytes(&nullifier_secret),
        recipient: recipient.clone(),
    };

    match emit_nullifier(&mut account, request_body).await {
        Ok(_) => Ok(format!("Relationship with {} nullified", recipient)),
        Err(e) => Err(e),
    }
}

/**
 * Retrieve the current nonce for the account and synchronize it with the locally stored account
 */
pub async fn synchronize_nonce() -> Result<String, GrapevineError> {
    // get the account
    let mut account = get_account()?;
    // build nonce request body
    let body = account.get_nonce_request();
    // send nonce request
    let res = get_nonce_req(body).await;
    let expected_nonce = match res {
        Ok(nonce) => nonce,
        Err(e) => return Err(e),
    };
    match expected_nonce == account.nonce() {
        true => Ok(format!(
            "Nonce is already synchronized at \"{}\"",
            expected_nonce
        )),
        false => {
            let msg = format!(
                "Local nonce of \"{}\" synchronized to \"{}\" from server",
                account.nonce(),
                expected_nonce
            );
            account
                .set_nonce(expected_nonce, Some((&**ACCOUNT_PATH).to_path_buf()))
                .unwrap();
            Ok(msg)
        }
    }
}

pub async fn get_my_proofs() -> Result<String, GrapevineError> {
    // get account
    let mut account = get_account()?;
    // sync nonce
    synchronize_nonce().await?;
    // send request
    let proofs = match get_proven_degrees_req(&mut account).await {
        Ok(data) => data,
        Err(e) => return Err(e),
    };

    if proofs.len() == 0 {
        Ok(String::from("No existing degree proofs."))
    } else {
        let degree_col_width = 8;
        let relation_col_width = 4;

        // calculate longest scope username
        let scope_col_width = proofs.iter().fold(0, |acc, x| {
            if acc < x.scope.len() {
                x.scope.len()
            } else {
                acc
            }
        }) + 8;

        let mut output = String::new();

        let str = format!(
            "{: <degree_col_width$} {: <scope_col_width$} {: <relation_col_width$}\n\n",
            "Degree", "Scope", "Preceding Relation"
        );
        output.push_str(&str);
        for proof in proofs {
            output.push_str(&format!(
                "{: <degree_col_width$} {: <scope_col_width$} {: <relation_col_width$}\n",
                proof.degree, proof.scope, proof.relation
            ));
        }
        Ok(output)
    }
}

pub async fn get_proof_metadata_by_scope(username: &String) -> Result<String, GrapevineError> {
    // get account
    let mut account = get_account()?;
    // sync nonce
    synchronize_nonce().await?;
    // send request
    let metadata = match get_degree_by_scope_req(&mut account, username).await {
        Ok(data) => data,
        Err(e) => return Err(e),
    };

    let degree_col_width = 8;
    let relation_col_width = 4;
    let scope_col_width = metadata.scope.len() + 8;

    let mut output = String::new();
    let col_labels = format!(
        "{: <degree_col_width$} {: <scope_col_width$} {: <relation_col_width$}\n\n",
        "Degree", "Scope", "Preceding Relation"
    );
    let col_values = format!(
        "{: <degree_col_width$} {: <scope_col_width$} {: <relation_col_width$}\n\n",
        metadata.degree, metadata.scope, metadata.relation
    );
    output.push_str(&col_labels);
    output.push_str(&col_values);
    Ok(output)
}

pub fn make_or_get_account(username: String) -> Result<GrapevineAccount, GrapevineError> {
    // get grapevine path
    let grapevine_dir_path = match std::env::var("HOME") {
        Ok(home) => Path::new(&home).join(".grapevine"),
        Err(_) => {
            return Err(GrapevineError::FsError(String::from(
                "Couldn't find home directory??",
            )))
        }
    };
    // if ~/.grapevine doesn't exist, create it
    if !grapevine_dir_path.exists() {
        std::fs::create_dir(grapevine_dir_path.clone()).unwrap();
    };
    let grapevine_account_path = grapevine_dir_path.join("grapevine.key");
    // check if grapevine.key exists and pull
    let account = match grapevine_account_path.exists() {
        true => match GrapevineAccount::from_fs(grapevine_account_path) {
            Ok(account) => account,
            Err(_) => {
                return Err(GrapevineError::FsError(String::from(
                    "Error reading existing Grapevine account from filesystem",
                )))
            }
        },
        false => {
            let account = GrapevineAccount::new(username);
            let json = serde_json::to_string(&account).unwrap();
            std::fs::write(&grapevine_account_path, json).unwrap();
            println!(
                "Created Grapevine account at {}",
                grapevine_account_path.display()
            );
            account
        }
    };
    // get_account_info();
    Ok(account)
}

pub async fn health() -> Result<String, GrapevineError> {
    println!("SERVER URL IS: {}", &**crate::http::SERVER_URL);
    // ensure artifacts exist
    artifacts_guard().await.unwrap();
    // get health status
    reqwest::get(&**crate::http::SERVER_URL)
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    return Ok("Health check passed".to_string());
}

/**
 * Attempts to get Grapevine account from fs and fails if it cannot
 *
 * @returns - the Grapevine account
 */
pub fn get_account() -> Result<GrapevineAccount, GrapevineError> {
    // get grapevine path
    let grapevine_account_path = Path::new(&std::env::var("HOME").unwrap())
        .join(".grapevine")
        .join("grapevine.key");
    // if ~/.grapevine doesn't exist, create it
    match grapevine_account_path.exists() {
        true => match GrapevineAccount::from_fs(grapevine_account_path) {
            Ok(account) => Ok(account),
            Err(_) => Err(GrapevineError::FsError(String::from(
                "Error reading existing Grapevine account from filesystem",
            ))),
        },
        false => {
            return Err(GrapevineError::FsError(String::from(
                "No Grapevine account found",
            )));
        }
    }
}
