use futures::stream::StreamExt;
use futures::TryStreamExt;
use grapevine_common::errors::GrapevineError;
use grapevine_common::http::responses::ProofMetadata;
use grapevine_common::models::{
    DegreeProofValidationData, GrapevineProof, ProvingData, Relationship, User,
};
use mongodb::bson::{self, doc, oid::ObjectId, Binary, Bson};
use mongodb::options::{
    ClientOptions, FindOneOptions, FindOptions, ServerApi, ServerApiVersion, UpdateOptions,
};
use mongodb::{Client, Collection};

use crate::utils::{RelationshipStatus, ToBson};
use crate::MONGODB_URI;

pub struct GrapevineDB {
    users: Collection<User>,
    relationships: Collection<Relationship>,
    proofs: Collection<GrapevineProof>,
}

mod pipelines;

impl GrapevineDB {
    pub async fn init(database_name: &String, mongodb_uri: &String) -> Self {
        let mut client_options = ClientOptions::parse(mongodb_uri).await.unwrap();
        let server_api = ServerApi::builder().version(ServerApiVersion::V1).build();
        client_options.server_api = Some(server_api);
        let client = Client::with_options(client_options).unwrap();
        let db = client.database(database_name);
        let users = db.collection("users");
        let relationships = db.collection("relationships");
        let proofs = db.collection("proofs");
        Self {
            users,
            relationships,
            proofs,
        }
    }

    /**
     * Drops the entire database to start off with clean state for testing
     */
    pub async fn drop(database_name: &str) {
        let mut client_options = ClientOptions::parse(&**MONGODB_URI).await.unwrap();
        let server_api = ServerApi::builder().version(ServerApiVersion::V1).build();
        client_options.server_api = Some(server_api);
        let client = Client::with_options(client_options).unwrap();

        client.database(database_name).drop(None).await.unwrap();
    }

    /// USER FUNCTIONS ///

    pub async fn increment_nonce(&self, username: &str) -> Result<(), GrapevineError> {
        let filter = doc! { "username": username };
        let update = doc! { "$inc": { "nonce": 1 } };
        match self.users.update_one(filter, update, None).await {
            Ok(_) => Ok(()),
            Err(e) => Err(GrapevineError::MongoError(e.to_string())),
        }
    }

    pub async fn get_nonce(&self, username: &str) -> Option<(u64, [u8; 32])> {
        // Verify user existence
        let filter = doc! { "username": username };
        // TODO: Projection doesn't work without pubkey due to BSON deserialization error
        let projection = doc! { "nonce": 1, "pubkey": 1, "address": 1 };
        let find_options = FindOneOptions::builder().projection(projection).build();
        let user = self
            .users
            .find_one(filter, Some(find_options))
            .await
            .unwrap();
        match user {
            Some(user) => Some((user.nonce.unwrap(), user.pubkey.unwrap())),
            None => None,
        }
    }

    /**
     * Queries the DB for documents where username OR pubkey matches an existing document
     * @dev used in user creation. If true, then fail to create the user
     *
     * @param username - the username to check for existence
     * @param pubkey - the pubkey to check
     * @returns - true or false if [username, pubkey] exists in d
     */
    pub async fn check_creation_params(
        &self,
        username: &String,
        pubkey: &[u8; 32],
    ) -> Result<[bool; 2], GrapevineError> {
        // Verify user existence
        let query = doc! {
            "$or": [
                { "username": username },
                { "pubkey": pubkey.to_vec().to_bson() }
            ]
        };
        let projection = doc! { "username": 1, "pubkey": 1, "address": 1 };
        let find_options = FindOptions::builder().projection(projection).build();
        let mut cursor = self.users.find(query, Some(find_options)).await.unwrap();
        let mut found = [false; 2];
        while let Some(result) = cursor.next().await {
            match result {
                Ok(user) => {
                    // Check if the username matches
                    if &user.username.unwrap() == username {
                        found[0] = true;
                    }
                    // Check if the pubkey matches
                    if &user.pubkey.unwrap() == pubkey {
                        found[1] = true;
                    }
                }
                Err(e) => return Err(GrapevineError::MongoError(e.to_string())),
            }
        }
        Ok(found)
    }

    /**
     * Insert a new user into the database
     * @notice - assumes username and pubkey auth checks were already performed
     *
     * @param user - the user to insert into the database
     * @returns - an error if the user already exists, or Ok otherwise
     */
    pub async fn create_user(&self, user: User) -> Result<ObjectId, GrapevineError> {
        // check if the username exists already in the database
        let query = doc! { "username": &user.username };
        let options = FindOneOptions::builder()
            .projection(doc! {"_id": 1})
            .build();
        // insert the user into the collection
        match self.users.insert_one(&user, None).await {
            Ok(result) => Ok(result.inserted_id.as_object_id().unwrap()),
            Err(e) => Err(GrapevineError::MongoError(e.to_string())),
        }
    }

    /**
     * Returns a user from a provided username
     *
     * @param username - username of the inteded user to fetch
     * @returns - user or none
     */
    pub async fn get_user(&self, username: &String) -> Option<User> {
        let filter = doc! { "username": username };
        let projection = doc! { "degree_proofs": 0 };
        let find_options = FindOneOptions::builder().projection(projection).build();
        self.users
            .find_one(filter, Some(find_options))
            .await
            .unwrap()
    }

    /**
     * Returns all the information needed for validating a degree proof
     * @dev returns 404 if the proof does not exist
     *
     * @param username - the username of the requesting user
     * @param proof - the object id of the degree proof
     *
     * @returns: all data used to validate proof being added to chain if proof found, or None
     */
    pub async fn get_degree_data(
        &self,
        username: &String,
        proof: &ObjectId,
    ) -> Option<DegreeProofValidationData> {
        // find degree chains they are not a part of
        let pipeline = pipelines::degree_data(&username, &proof);
        // get the OID's of degree proofs the user can build from
        let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
        if let Some(result) = cursor.next().await {
            match result {
                Ok(document) => Some(bson::from_bson(bson::Bson::Document(document)).unwrap()),
                Err(_) => None,
            }
        } else {
            None
        }
    }

    /**
     * Get the pubkey and the address of a user
     *
     * @param username - the username of the user to get the pubkey for
     * @return - (compressed pubkey, address)
     */
    pub async fn get_pubkey(&self, username: &String) -> Option<([u8; 32], [u8; 32])> {
        let filter = doc! { "username": username };
        let projection = doc! { "pubkey": 1, "address": 1 };
        let find_options = FindOneOptions::builder().projection(projection).build();
        let user = self
            .users
            .find_one(filter, Some(find_options))
            .await
            .unwrap();
        match user {
            Some(user) => Some((user.pubkey.unwrap(), user.address.unwrap())),
            None => None,
        }
    }

    /**
     * Adds a relationship to the relationship collection
     * @notice - can be pending or active depending on whether set by the doc passed in
     *
     * @param - relationship to add
     * @returns - empty result on success and error on failure
     */
    pub async fn add_relationship(
        &self,
        relationship: &Relationship,
    ) -> Result<(), GrapevineError> {
        match self.relationships.insert_one(relationship, None).await {
            Ok(_) => Ok(()),
            Err(e) => Err(GrapevineError::MongoError(e.to_string())),
        }
    }

    /**
     * Sets pending relationship document to be active
     *
     * @param sender - the sender of the relationship document
     * @param recipient - the recipient of the relationship document
     * @returns - () or error
     */
    pub async fn activate_relationship(
        &self,
        sender: &ObjectId,
        recipient: &ObjectId,
    ) -> Result<(), GrapevineError> {
        // try to update the document
        let filter = doc! { "sender": sender, "recipient": recipient, "active": false };
        let update = doc! { "$set": { "active": true }};
        let result = self.relationships.update_one(filter, update, None).await;
        // check if successful
        match result {
            Ok(result) => match result.matched_count {
                1 => Ok(()),
                _ => Err(GrapevineError::NoPendingRelationship(
                    sender.to_hex(),
                    recipient.to_hex(),
                )),
            },
            Err(e) => Err(GrapevineError::MongoError(e.to_string())),
        }
    }
    /**
     * Delete a pending relationship from one user to another
     * @notice relationship must be pending / not active
     *         Relationships cannot be removed since degree proofs may be built from them
     *
     * @param from - the user enabling relationship
     * @param to - the user receiving relationship
     * @returns - Ok if successful, Err otherwise
     */
    pub async fn reject_relationship(
        &self,
        from: &String,
        to: &String,
    ) -> Result<(), GrapevineError> {
        // setup aggregation pipeline to get the ObjectID of the pending relationship to delete
        let pipeline = pipelines::reject_relationship(from, to);

        // get the OID of the pending relationship to delete
        let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
        let oid: ObjectId = match cursor.next().await {
            Some(Ok(document)) => document
                .get("relationship")
                .unwrap()
                .as_object_id()
                .unwrap(),
            Some(Err(e)) => return Err(GrapevineError::MongoError(e.to_string())),
            None => {
                return Err(GrapevineError::NoPendingRelationship(
                    from.clone(),
                    to.clone(),
                ))
            }
        };

        // delete the pending relationship
        let filter = doc! { "_id": oid };
        match self.relationships.delete_one(filter, None).await {
            Ok(res) => match res.deleted_count == 1 {
                true => (),
                false => {
                    return Err(GrapevineError::MongoError(
                        "Failed to delete relationship".to_string(),
                    ))
                }
            },
            Err(e) => return Err(GrapevineError::MongoError(e.to_string())),
        }

        Ok(())
    }

    /**
     * Returns a relationship from a specified sender and recipient username
     *
     * @param sender - username of the sender
     * @param recipient - username of the recipient
     *
     * @returns - relationship on success or error
     */
    pub async fn get_relationship(
        &self,
        sender: &String,
        recipient: &String,
    ) -> Result<Relationship, GrapevineError> {
        // find a relationship document given a sender and recipient username
        let pipeline = pipelines::get_relationship(&sender, &recipient, true);
        let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
        // try to parse the returned relationship document
        if let Some(result) = cursor.next().await {
            match result {
                Ok(document) => Ok(bson::from_bson(bson::Bson::Document(document)).unwrap()),
                Err(e) => Err(GrapevineError::MongoError(e.to_string())),
            }
        } else {
            return Err(GrapevineError::NoRelationship(
                sender.clone(),
                recipient.clone(),
            ));
        }
    }

    /**
     * Nullifies a relationship by adding an emitted nullifier
     *
     * @param nullifier - the nullifier to add to the relationship document
     * @param sender - the username of the sender (nullifier emitter)
     * @param recipient - the username of the recipient (nullifier users)
     */
    pub async fn nullify_relationship(
        &self,
        nullifier: &[u8; 32],
        sender: &String,
        recipient: &String,
    ) -> Result<(), GrapevineError> {
        // setup aggregation pipeline for finding the
        let pipeline = pipelines::get_relationship(&sender, &recipient, false);
        // get oid for relationship
        let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
        if let Some(result) = cursor.next().await {
            match result {
                Ok(document) => {
                    // update relationship document by adding emitted nullifier
                    let query = doc! {"_id": document.get("_id").unwrap() };
                    let update =
                        doc! { "$set": { "emitted_nullifier": nullifier.to_vec().to_bson() }};
                    match self.relationships.update_one(query, update, None).await {
                        Ok(_) => Ok(()),
                        Err(e) => Err(GrapevineError::MongoError(e.to_string())),
                    }
                }
                Err(e) => return Err(GrapevineError::MongoError(e.to_string())),
            }
        } else {
            // TODO: Create relationship not found type
            Err(GrapevineError::MongoError(
                "Relationship not found".to_string(),
            ))
        }
    }

    /**
     * Find all usernames for (pending or active) relationships for a user
     *
     * @param user - the username of the user to find relationships for
     * @param active - whether to find active or pending relationships
     * @returns - a list of usernames of the users the user has relationships with
     */
    pub async fn get_all_relationship_usernames(
        &self,
        user: &String,
        active: bool,
    ) -> Result<Vec<String>, GrapevineError> {
        // setup aggregation pipeline for finding usernames of relationships
        let pipeline = pipelines::get_relationships_usernames(&user, active);
        // get the OID's of degree proofs the user can build from
        let mut relationships: Vec<String> = vec![];
        let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
        while let Some(result) = cursor.next().await {
            match result {
                Ok(document) => {
                    let username = document.get("username").unwrap().as_str().unwrap();
                    relationships.push(username.to_string());
                }
                Err(e) => println!("Error: {}", e),
            }
        }
        Ok(relationships)
    }

    /**
     * Determines whether a pending relationship
     * @notice: preceded by two "get_user" calls, could be combined into one query
     *          that finds both users and the pending relaitonship
     *
     * @param from - the OID of the user enabling relationship
     * @param to - the OID of the user receiving relationship
     * @returns - enum denoting whether relationship is active, pending, or nonexistent
     */
    pub async fn relationship_status(
        &self,
        from: &ObjectId,
        to: &ObjectId,
    ) -> Result<RelationshipStatus, GrapevineError> {
        // Query to find pending relationship
        let filter = doc! { "sender": from, "recipient": to };
        let projection = doc! { "_id": 1, "active": 1 };
        let find_options = FindOneOptions::builder().projection(projection).build();
        // check if the relationship exists
        match self.relationships.find_one(filter, find_options).await {
            Ok(res) => match res {
                Some(document) => {
                    // determine whether found relationship is active or pending
                    match document.active.unwrap() {
                        true => Ok(RelationshipStatus::Active),
                        false => Ok(RelationshipStatus::Pending),
                    }
                }
                None => Ok(RelationshipStatus::None),
            },
            Err(e) => Err(GrapevineError::MongoError(e.to_string())),
        }
    }

    /**
     * Adds an identity proof for a given user
     *
     * @param user - the user to add an identity proof for
     * @param proof - the identity proof to add for them
     * @return - the object id of the proof if successful, and the error otherwise
     */
    pub async fn add_identity_proof(
        &self,
        user: &ObjectId,
        proof: GrapevineProof,
    ) -> Result<ObjectId, GrapevineError> {
        // ensure that there is not an existing proof with the given user as the scope
        let find_options = FindOneOptions::builder().sort(doc! {"_id": 1}).build();
        let filter = doc! { "scope": user };
        if let Ok(res) = self.users.find_one(filter, find_options).await {
            if res.is_some() {
                return Err(GrapevineError::InternalError);
            };
        } else {
            return Err(GrapevineError::InternalError);
        };

        // add the proof document
        match self.proofs.insert_one(proof, None).await {
            Ok(res) => Ok(res.inserted_id.as_object_id().unwrap()),
            Err(_) => Err(GrapevineError::InternalError),
        }
    }

    pub async fn add_degree_proof(
        &self,
        proof: &GrapevineProof,
    ) -> Result<ObjectId, GrapevineError> {
        // set up pipeline to handle updating the social graph
        let scope = proof.scope.clone().unwrap();
        let relation = proof.relation.clone().unwrap();
        let pipeline = pipelines::degree_proof_dependencies(&scope, &relation);
        let mut cursor = self.proofs.aggregate(pipeline, None).await.unwrap();
        let mut set_inactive: Option<ObjectId> = None;
        let mut remove: Vec<ObjectId> = vec![];
        // figure out how to handle the social graph
        while let Some(result) = cursor.next().await {
            match result {
                Ok(document) => {
                    let removable = document.get("removable").unwrap().as_bool().unwrap();
                    let id = document.get("_id").unwrap().as_object_id().unwrap();
                    let downstream = document.get("downstream").unwrap().as_array().unwrap();
                    let downstream: Vec<ObjectId> = downstream
                        .iter()
                        .filter_map(|item| item.as_object_id())
                        .collect();
                    if !removable {
                        if set_inactive.is_none() && remove.len() == 0 {
                            set_inactive = Some(id);
                        }
                        break;
                    } else {
                        remove.push(id);
                        remove.extend(downstream);
                    }
                }
                Err(e) => return Err(GrapevineError::MongoError(e.to_string())),
            }
        }

        if set_inactive.is_some() {
            // set_inactive should never be Some while remove is not empty
            if remove.len() > 0 {
                println!("Degree Query Machine Broke");
                return Err(GrapevineError::InternalError);
            }
            // update the proof to be inactive
            let query = doc! { "_id": set_inactive.unwrap() };
            let update = doc! { "$set": { "inactive": true }};
            self.proofs.update_one(query, update, None).await.unwrap();
        } else if remove.len() > 0 {
            // delete all the proofs that have no downstream dependencies
            let filter = doc! { "_id": { "$in": remove.iter().map(|id| Bson::ObjectId(id.clone())).collect::<Vec<Bson>>() }};
            self.proofs.delete_many(filter, None).await.unwrap();
        }

        // create new proof document
        let proof_oid = self
            .proofs
            .insert_one(proof, None)
            .await
            .unwrap()
            .inserted_id
            .as_object_id()
            .unwrap();
        Ok(proof_oid)
    }

    /**
     * Given a user, find all degree proofs they have created that are currently active
     *
     * @param username - the username of the user to find active proofs for
     * @returns - a list of proof metadata
     */
    pub async fn get_proven_degrees(
        &self,
        username: String,
    ) -> Result<Vec<ProofMetadata>, GrapevineError> {
        let pipeline = pipelines::get_proven_degrees(&username);
        let mut proofs: Vec<ProofMetadata> = vec![];
        let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
        while let Some(result) = cursor.next().await {
            match result {
                Ok(document) => {
                    proofs.push(bson::from_document(document).unwrap());
                }
                Err(e) => return Err(GrapevineError::MongoError(e.to_string())),
            }
        }
        Ok(proofs)
    }

    /**
     * Given a user, find available degrees of separation proofs they can build from
     *   - find degree chains they are not a part of
     *   - find lower degree proofs they can build from
     *
     * @param username - the username of the user to find available proofs for
     * @returns - a list of available proofs the user can build from with metadata for ui
     */
    pub async fn find_available_degrees(&self, username: String) -> Vec<ProofMetadata> {
        // find degree chains they are not a part of
        let pipeline = pipelines::available_degrees(&username);
        // get the OID's of degree proofs the user can build from
        let mut available_proofs: Vec<ProofMetadata> = vec![];
        let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
        while let Some(result) = cursor.next().await {
            match result {
                Ok(document) => available_proofs.push(bson::from_document(document).unwrap()),
                Err(e) => println!("Error: {}", e),
            }
        }
        available_proofs
    }

    pub async fn find_proof_by_scope(
        &self,
        username: &String,
        scope: &String,
    ) -> Option<GrapevineProof> {
        // pipeline to retrieve proof given relation = username and scope = scope
        let pipeline = pipelines::proof_by_scope(username, scope);
        // try to get the returned proof
        let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
        if let Some(result) = cursor.next().await {
            match result {
                Ok(document) => Some(bson::from_bson(bson::Bson::Document(document)).unwrap()),
                Err(_) => None,
            }
        } else {
            None
        }
    }

    /**
     * Get a proof from the server with all info needed to prove a degree of separation as a given user
     *
     * @param username - the username of the user proving a degree of separation
     * @param oid - the id of the proof to get
     */
    pub async fn get_proof_and_data(
        &self,
        username: String,
        proof: ObjectId,
    ) -> Option<ProvingData> {
        // pipeline to get the proof data
        let pipeline = pipelines::proving_data(&username, &proof);
        // Get the proving data
        let mut cursor = self.proofs.aggregate(pipeline, None).await.unwrap();
        if let Some(result) = cursor.next().await {
            match result {
                Ok(document) => Some(bson::from_bson(bson::Bson::Document(document)).unwrap()),
                Err(_) => None,
            }
        } else {
            None
        }
    }

    /**
    * Get details on account:
       - # of first degree connections
       - # of second degree connections
       - # of phrases created
    */
    pub async fn get_account_details(&self, user: &ObjectId) -> Option<(u64, u64, u64)> {
        let mut cursor = self
            .users
            .aggregate(pipelines::get_account_details(user), None)
            .await
            .unwrap();

        match cursor.next().await.unwrap() {
            Ok(stats) => {
                let phrase_count = stats.get_i32("phrase_count").unwrap();
                let first_degree_connections = stats.get_i32("first_degree_connections").unwrap();
                let second_degree_connections = stats.get_i32("second_degree_connections").unwrap();
                return Some((
                    phrase_count as u64,
                    first_degree_connections as u64,
                    second_degree_connections as u64,
                ));
            }
            Err(e) => {
                println!("Error: {:?}", e);
                return None;
            }
        }
    }

    /**
     * Deletes all proofs that have matching nullifiers
     *
     * @param nullifier - the nullifier to match
     * @returns - the number of proofs deleted
     */
    pub async fn delete_nullified_proofs(
        &self,
        nullifier: &[u8; 32],
    ) -> Result<u64, GrapevineError> {
        // filter to find all matching nullifiers
        let filter = doc! {
            "nullifiers": {
                "$elemMatch": {
                    "$eq": Bson::Array(nullifier.iter().map(|&byte| Bson::Int32(byte.into())).collect())
                }
            }
        };
        match self.proofs.delete_many(filter, None).await {
            Ok(result) => Ok(result.deleted_count),
            Err(e) => {
                println!("Error: {}", e);
                Err(GrapevineError::MongoError(e.to_string()))
            }
        }
    }

    /**
     * Determines whether any nullifiers for a given proof are emitted in relationships
     *
     * @param nullifiers - the nullifiers to search for
     * @returns - if successful, a boolean whether or not the nullifiers are not emitted (true = emitted)
     */
    pub async fn contains_emitted_nullifiers(
        &self,
        nullifiers: &Vec<[u8; 32]>,
    ) -> Result<bool, GrapevineError> {
        // pipeline for searching all given nullifiers in emitted nullifiers from relationships
        let pipeline = pipelines::nullifiers_emitted(&nullifiers);
        // determine if any matching nullifiers were found
        let mut cursor = self.relationships.aggregate(pipeline, None).await.unwrap();
        if let Some(result) = cursor.next().await {
            match result {
                Ok(doc) => Ok(doc.get("matchedCount").unwrap().as_i32().unwrap() != 0),
                Err(e) => Err(GrapevineError::MongoError(e.to_string())),
            }
        } else {
            Ok(false)
        }
    }
}
