use futures::stream::StreamExt;
use futures::TryStreamExt;
use grapevine_common::errors::GrapevineError;
use grapevine_common::http::responses::DegreeData;
use grapevine_common::models::{GrapevineProof, Relationship, User};
use mongodb::bson::{self, doc, oid::ObjectId, Binary, Bson};
use mongodb::options::{ClientOptions, FindOneOptions, FindOptions, ServerApi, ServerApiVersion};
use mongodb::{Client, Collection};

use crate::utils::serialize_bytes_to_bson;
use crate::MONGODB_URI;

pub struct GrapevineDB {
    users: Collection<User>,
    relationships: Collection<Relationship>,
    proofs: Collection<GrapevineProof>,
}

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
        let pubkey_binary = Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: pubkey.to_vec(),
        };
        let query = doc! {
            "$or": [
                { "username": username },
                { "pubkey": pubkey_binary }
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

    pub async fn get_user(&self, username: &String) -> Option<User> {
        let filter = doc! { "username": username };
        let projection = doc! { "degree_proofs": 0 };
        let find_options = FindOneOptions::builder().projection(projection).build();
        self.users
            .find_one(filter, Some(find_options))
            .await
            .unwrap()
    }

    // pub async fn get_pubkey(&self, username: String) -> Option<[u8; 32]> {
    //     let filter = doc! { "username": username };
    //     let projection = doc! { "pubkey": 1 };
    //     let find_options = FindOneOptions::builder().projection(projection).build();
    //     let user = self
    //         .users
    //         .find_one(filter, Some(find_options))
    //         .await
    //         .unwrap();
    //     match user {
    //         Some(user) => Some(user.pubkey.unwrap()),
    //         None => None,
    //     }
    // }

    pub async fn add_pending_relationship(
        &self,
        relationship: &Relationship,
    ) -> Result<(), GrapevineError> {
        // create new relationship document
        match self.relationships.insert_one(relationship, None).await {
            Ok(_) => Ok(()),
            Err(e) => Err(GrapevineError::MongoError(e.to_string())),
        }
    }

    /**
     * Sets pending relationship to be active (to -> from) and creates a new relationship (from -> to)
     *
     * @param relationship - the relationship to activate
     * @returns - the object id of the activated relationship
     */
    pub async fn activate_relationship(
        &self,
        from_relationship: &Relationship,
        to_relationship: &Relationship,
    ) -> Result<(), GrapevineError> {
        let from_query = doc! {
            "sender": from_relationship.sender.unwrap(),
            "recipient": from_relationship.recipient.unwrap()
        };

        let to_query = doc! {
            "sender": to_relationship.sender.unwrap(),
            "recipient": to_relationship.recipient.unwrap()
        };

        let find_options = FindOneOptions::builder()
            .projection(doc! {"_id": 1})
            .build();

        // retrived oid for "from" relationship
        let from_oid: Bson = self
            .relationships
            .find_one(from_query, Some(find_options.clone()))
            .await
            .unwrap()
            .unwrap()
            .id
            .unwrap()
            .into();

        let to_oid: Bson = self
            .relationships
            .find_one(to_query, Some(find_options))
            .await
            .unwrap()
            .unwrap()
            .id
            .unwrap()
            .into();

        let from_update = doc! {
            "$set": {
                "active": true,
                "encrypted_nullifier_secret": Bson::Binary(Binary {
                    subtype: bson::spec::BinarySubtype::Generic,
                    bytes: from_relationship.encrypted_nullifier_secret.unwrap().to_vec(),
                })
            }
        };

        let to_update = doc! {
            "$set": {
                "active": true,
                "encrypted_auth_signature": Bson::Binary(Binary {
                    subtype: bson::spec::BinarySubtype::Generic,
                    bytes: to_relationship.encrypted_auth_signature.unwrap().to_vec(),
                }),
                "encrypted_nullifier": Bson::Binary(Binary {
                    subtype: bson::spec::BinarySubtype::Generic,
                    bytes: to_relationship.encrypted_nullifier.unwrap().to_vec(),
                }),
                "ephemeral_key": Bson::Binary(Binary {
                    subtype: bson::spec::BinarySubtype::Generic,
                    bytes: to_relationship.ephemeral_key.unwrap().to_vec(),
                }),
            }
        };

        // update "from" relationship
        match self
            .relationships
            .update_one(doc! {"_id": from_oid.clone()}, from_update, None)
            .await
        {
            Ok(_) => (),
            Err(e) => return Err(GrapevineError::MongoError(e.to_string())),
        };

        // update "to" relationship
        match self
            .relationships
            .update_one(doc! {"_id": to_oid.clone()}, to_update, None)
            .await
        {
            Ok(_) => (),
            Err(e) => return Err(GrapevineError::MongoError(e.to_string())),
        };

        // push the relationship to the sender's list of relationships
        let query = doc! { "_id": from_relationship.sender.unwrap() };
        let update = doc! { "$push": { "relationships": from_oid } };
        match self.users.update_one(query, update, None).await {
            Ok(_) => (),
            Err(e) => return Err(GrapevineError::MongoError(e.to_string())),
        }

        // push the relationship to the recipients's list of relationships
        let query = doc! { "_id": to_relationship.sender.unwrap() };
        let update = doc! { "$push": { "relationships": to_oid } };
        match self.users.update_one(query, update, None).await {
            Ok(_) => (),
            Err(e) => return Err(GrapevineError::MongoError(e.to_string())),
        }
        Ok(())
    }

    // /**
    //  * Delete a pending relationship from one user to another
    //  * @notice relationship must be pending / not active
    //  *         Relationships cannot be removed since degree proofs may be built from them
    //  *
    //  * @param from - the user enabling relationship
    //  * @param to - the user receiving relationship
    //  * @returns - Ok if successful, Err otherwise
    //  */
    // pub async fn reject_relationship(
    //     &self,
    //     from: &String,
    //     to: &String,
    // ) -> Result<(), GrapevineError> {
    //     // setup aggregation pipeline to get the ObjectID of the pending relationship to delete
    //     let pipeline = vec![
    //         // get the ObjectID of the recipient of the relationship request
    //         doc! { "$match": { "username": to } },
    //         doc! { "$project": { "_id": 1 } },
    //         // lookup the ObjectID of the sender of the relationship request
    //         doc! {
    //             "$lookup": {
    //                 "from": "users",
    //                 "let": { "from": from },
    //                 "as": "sender",
    //                 "pipeline": [
    //                     doc! { "$match": { "$expr": { "$eq": ["$username", "$$from"] } } },
    //                     doc! { "$project": { "_id": 1 } }
    //                 ],
    //             }
    //         },
    //         doc! { "$unwind": "$sender" },
    //         // project the ObjectID's of the sender and recipient
    //         doc! { "$project": { "recipient": "$_id", "sender": "$sender._id" } },
    //         // lookup the ObjectID of the pending relationship to delete
    //         doc! {
    //             "$lookup": {
    //                 "from": "relationships",
    //                 "let": { "sender": "$sender", "recipient": "$recipient" },
    //                 "as": "relationship",
    //                 "pipeline": [
    //                     doc! {
    //                         "$match": {
    //                             "$expr": {
    //                                 "$and": [
    //                                     { "$eq": ["$sender", "$$sender"] },
    //                                     { "$eq": ["$recipient", "$$recipient"] },
    //                                     { "$eq": ["$active", false ] }
    //                                 ]
    //                             }
    //                         }
    //                     },
    //                     doc! { "$project": { "_id": 1 } }
    //                 ],
    //             }
    //         },
    //         doc! { "$unwind": "$relationship" },
    //         // project the ObjectID of the pending relationship to delete
    //         doc! { "$project": { "relationship": "$relationship._id", "_id": 0 } },
    //     ];

    //     // get the OID of the pending relationship to delete
    //     let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
    //     let oid: ObjectId = match cursor.next().await {
    //         Some(Ok(document)) => {
    //             println!("FOUND DOC: {:?}", document);
    //             document
    //                 .get("relationship")
    //                 .unwrap()
    //                 .as_object_id()
    //                 .unwrap()
    //         }
    //         Some(Err(e)) => return Err(GrapevineError::MongoError(e.to_string())),
    //         None => {
    //             return Err(GrapevineError::NoPendingRelationship(
    //                 from.clone(),
    //                 to.clone(),
    //             ))
    //         }
    //     };

    //     // delete the pending relationship
    //     let filter = doc! { "_id": oid };
    //     match self.relationships.delete_one(filter, None).await {
    //         Ok(res) => match res.deleted_count == 1 {
    //             true => (),
    //             false => {
    //                 return Err(GrapevineError::MongoError(
    //                     "Failed to delete relationship".to_string(),
    //                 ))
    //             }
    //         },
    //         Err(e) => return Err(GrapevineError::MongoError(e.to_string())),
    //     }

    //     Ok(())
    // }

    pub async fn get_relationship(
        &self,
        sender: &String,
        recipient: &String,
    ) -> Result<Relationship, GrapevineError> {
        // TODO: Make this into aggregation pipeline
        let find_options = FindOptions::builder()
            .projection(doc! {"_id": 1, "username": 1, "pubkey": 1, "address": 1 })
            .build();
        let usernames = [sender, recipient];
        let bson_usernames: Vec<Bson> = usernames
            .iter()
            .map(|u| Bson::String(u.to_string()))
            .collect();
        // Get sender and recipient oids
        let mut cursor = self
            .users
            .find(doc! {"username": {"$in": bson_usernames}}, find_options)
            .await
            .unwrap();

        let mut user_oids: Vec<(String, ObjectId)> = vec![];

        while let Some(result) = cursor.next().await {
            match result {
                Ok(document) => {
                    user_oids.push((document.username.unwrap(), document.id.unwrap()));
                }
                Err(e) => {
                    println!("Error: {:?}", e);
                }
            }
        }

        let relationship_query = match user_oids[0].0 == *sender {
            true => doc! { "sender": user_oids[0].1, "recipient": user_oids[1].1},
            false => doc! { "sender": user_oids[1].1, "recipient": user_oids[0].1},
        };

        match self.relationships.find_one(relationship_query, None).await {
            Ok(res) => Ok(res.unwrap()),
            Err(e) => Err(GrapevineError::MongoError(e.to_string())),
        }
    }

    pub async fn terminate_relationship(
        &self,
        nullifier: [u8; 32],
        sender: &String,
        recipient: &String,
    ) -> Result<(), GrapevineError> {
        // setup aggregation pipeline for finding usernames of relationships
        let pipeline = vec![
            // get the ObjectID of the user doc for the given username
            doc! {
                "$match": {
                    "username": { "$in": [recipient, sender] }
                }
            },
            doc! {
                "$project": {
                    "_id": 0,
                    "recipient": {
                        "$cond": { "if": { "$eq": ["$username", recipient] }, "then": "$_id", "else": "$$REMOVE" }
                    },
                    "sender": {
                        "$cond": { "if": { "$eq": ["$username", sender] }, "then": "$_id", "else": "$$REMOVE" }
                    }
                }
            },
            doc! {
                "$group": {
                    "_id": 0,
                    "recipient": { "$max": "$recipient" },
                    "sender": { "$max": "$sender" }
                }
            },
            // query relationship document
            doc! {
                "$lookup": {
                    "from": "relationships",
                    "let": { "sender_user": "$sender", "recipient_user": "$recipient" },
                    "pipeline": [
                        {
                            "$match": {
                                "$expr": {
                                    "$and": [
                                        { "$eq": ["$sender", "$$sender_user"] },
                                        { "$eq": ["$recipient", "$$recipient_user"] },
                                    ]
                                }
                            }
                        }
                    ],
                    "as": "relationship"
                }
            },
            doc! {
                "$unwind": "$relationship"
            },
            doc! {
                "$replaceRoot": {
                    "newRoot": "$relationship"
                }
            },
        ];

        // get oid for relationship
        let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();

        if let Some(result) = cursor.next().await {
            match result {
                Ok(document) => {
                    let relationship_id = document.get("_id").unwrap();

                    // update relationship document by adding emitted nullifier
                    self.relationships
                        .update_one(
                            doc! {"_id": relationship_id},
                            doc! {"$set": {"emitted_nullifier": serialize_bytes_to_bson(&nullifier)}},
                            None,
                        )
                        .await;

                    // remove relationship id from user document
                    self.users
                        .update_one(
                            doc! {"username": sender},
                            doc! {"$pull": {"relationships": relationship_id}},
                            None,
                        )
                        .await;
                }
                Err(e) => eprintln!("Error retrieving relationship: {}", e),
            }
        } else {
            println!("No relationship found.");
        }

        Ok(())
    }

    // /**
    //  * Find all (pending or active) relationships for a user
    //  *
    //  * @param user - the username of the user to find relationships for
    //  * @param active - whether to find active or pending relationships
    //  * @returns - a list of usernames of the users the user has relationships with
    //  */
    // pub async fn get_relationships(
    //     &self,
    //     user: &String,
    //     active: bool,
    // ) -> Result<Vec<String>, GrapevineError> {
    //     // setup aggregation pipeline for finding usernames of relationships
    //     let pipeline = vec![
    //         // get the ObjectID of the user doc for the given username
    //         doc! { "$match": { "username": user } },
    //         doc! { "$project": { "_id": 1 } },
    //         // lookup all (pending/ active) relationships for the user
    //         doc! {
    //             "$lookup": {
    //                 "from": "relationships",
    //                 "localField": "_id",
    //                 "foreignField": "recipient",
    //                 "as": "relationships",
    //                 "pipeline": [
    //                     doc! { "$match": { "$expr": { "$eq": ["$active", active] } } },
    //                     doc! { "$project": { "sender": 1, "_id": 0 } },
    //                 ],
    //             }
    //         },
    //         doc! { "$unwind": "$relationships" },
    //         // lookup the usernames of the relationships by the ObjectID found in the relationship docs
    //         doc! {
    //             "$lookup": {
    //                 "from": "users",
    //                 "localField": "relationships.sender",
    //                 "foreignField": "_id",
    //                 "as": "relationships",
    //                 "pipeline": [
    //                     doc! { "$project": { "username": 1, "_id": 0 } },
    //                 ],
    //             }
    //         },
    //         doc! { "$unwind": "$relationships" },
    //         // project only the usernames of the relationships
    //         doc! { "$project": { "username": "$relationships.username", "_id": 0 } },
    //     ];

    //     // get the OID's of degree proofs the user can build from
    //     let mut relationships: Vec<String> = vec![];
    //     let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
    //     while let Some(result) = cursor.next().await {
    //         match result {
    //             Ok(document) => {
    //                 let username = document.get("username").unwrap().as_str().unwrap();
    //                 relationships.push(username.to_string());
    //             }
    //             Err(e) => println!("Error: {}", e),
    //         }
    //     }
    //     Ok(relationships)
    // }

    /**
     * Attempts to find a relationship between to users
     *
     * @param from - the user enabling relationship
     * @param to - the user receiving relationship
     * @returns - the relationship if found, None otherwise
     */
    pub async fn find_pending_relationship(
        &self,
        from: &ObjectId,
        to: &ObjectId,
    ) -> Result<bool, GrapevineError> {
        let filter = doc! { "sender": from, "recipient": to, "active": false };
        let projection = doc! { "_id": 1 };
        let find_options = FindOneOptions::builder().projection(projection).build();
        match self.relationships.find_one(filter, find_options).await {
            Ok(res) => match res {
                Some(_) => Ok(true),
                None => Ok(false),
            },
            Err(e) => Err(GrapevineError::MongoError(e.to_string())),
        }
    }

    /**
     * Check to see if a relationship already exists between two users
     *
     * @param sender - the user enabling relationship
     * @param recipient - the user receiving relationship
     * @returns
     *  - 0: true if relationship from sender to user exists
     *  - 1: true if relationship is active
     */
    pub async fn check_relationship_exists(
        &self,
        sender: &ObjectId,
        recipient: &ObjectId,
    ) -> Result<(bool, bool), GrapevineError> {
        let query = doc! { "recipient": recipient, "sender": sender };
        let projection = doc! { "_id": 1, "active": 1 };
        let find_options = FindOneOptions::builder().projection(projection).build();

        match self.relationships.find_one(query, find_options).await {
            Ok(res) => {
                let exists = res.is_some();
                let active = match exists {
                    true => res.unwrap().active.unwrap(),
                    false => false,
                };
                Ok((exists, active))
            }
            Err(e) => Err(GrapevineError::MongoError(e.to_string())),
        }
    }

    // /**
    //  * Creates a new phrase document in the database
    //  * @notice assumes that `get_phrase_by_{hash, oid}` has already been called
    //  *
    //  * @param phrase_hash - the hash of the phrase to create
    //  * @param description - the description of the phrase
    //  * @return: (0, 1)
    //  *  - 0: the object id of the created phrase document
    //  *  - 1: the index of the phrase
    //  */
    // pub async fn create_phrase(
    //     &self,
    //     phrase_hash: [u8; 32],
    //     description: String,
    // ) -> Result<(ObjectId, u32), GrapevineError> {
    //     // query for the highest phrase id
    //     let find_options = FindOneOptions::builder().sort(doc! {"index": -1}).build();

    //     // Use find_one with options to get the document with the largest phrase_id
    //     let index = match self.phrases.find_one(None, find_options).await {
    //         Ok(Some(document)) => {
    //             let previous_index = document.index.unwrap();
    //             previous_index + 1
    //         }
    //         Ok(None) => 1,
    //         Err(e) => return Err(GrapevineError::MongoError(e.to_string())),
    //     };

    //     // create new phrase document
    //     let phrase = Phrase {
    //         id: None,
    //         index: Some(index),
    //         hash: Some(phrase_hash),
    //         description: Some(description),
    //     };
    //     let oid = match self.phrases.insert_one(&phrase, None).await {
    //         Ok(res) => res.inserted_id.as_object_id().unwrap(),
    //         Err(e) => return Err(GrapevineError::MongoError(e.to_string())),
    //     };

    //     Ok((oid, index))
    // }

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

    // pub async fn add_proof(
    //     &self,
    //     user: &ObjectId,
    //     proof: &DegreeProof,
    // ) -> Result<ObjectId, GrapevineError> {
    //     // fetch all proofs preceding this one
    //     let mut proof_chain: Vec<DegreeProof> = vec![];
    //     let mut cursor = self
    //         .degree_proofs
    //         .aggregate(
    //             vec![
    //                 doc! {
    //                   "$match": {
    //                     "user": user,
    //                     "phrase": proof.phrase
    //                   }
    //                 },
    //                 doc! {
    //                   "$graphLookup": {
    //                     "from": "degree_proofs",
    //                     "startWith": "$preceding", // Assuming 'preceding' is a field that points to the parent document
    //                     "connectFromField": "preceding",
    //                     "connectToField": "_id",
    //                     "as": "preceding_chain",
    //                   }
    //                 },
    //                 doc! {
    //                     "$project": {
    //                         "_id": 1,
    //                         "degree": 1,
    //                         "inactive": 1,
    //                         "preceding": 1,
    //                         "proceeding": 1,
    //                         "preceding_chain": {
    //                             "$map": {
    //                                 "input": "$preceding_chain",
    //                                 "as": "chain",
    //                                 "in": {
    //                                     "_id": "$$chain._id",
    //                                     "degree": "$$chain.degree",
    //                                     "inactive": "$$chain.inactive",
    //                                     "preceding": "$$chain.preceding",
    //                                     "proceeding": "$$chain.proceeding",
    //                                 }
    //                             }
    //                         }
    //                     }
    //                 },
    //             ],
    //             None,
    //         )
    //         .await
    //         .unwrap();
    //     while let Some(result) = cursor.next().await {
    //         match result {
    //             Ok(document) => {
    //                 let preceding_chain = document.get("preceding_chain");
    //                 let mut parsed: Vec<DegreeProof> = vec![];
    //                 if preceding_chain.is_some() {
    //                     parsed =
    //                         bson::from_bson::<Vec<DegreeProof>>(preceding_chain.unwrap().clone())
    //                             .unwrap();
    //                 }
    //                 let base_proof = bson::from_document::<DegreeProof>(document).unwrap();
    //                 proof_chain.push(base_proof);
    //                 proof_chain.append(&mut parsed);
    //             }
    //             Err(e) => println!("Error: {}", e),
    //         }
    //     }

    //     // Sort by degrees
    //     proof_chain.sort_by(|a, b| b.degree.cmp(&a.degree));

    //     let mut delete_entities: Vec<ObjectId> = vec![];
    //     // Tuple containing object id, inactive status, updated proceeding array
    //     let mut update_entitity: (ObjectId, bool, ObjectId) =
    //         (ObjectId::new(), false, ObjectId::new());

    //     // There may be multiple delete values but there will always be one update
    //     let mut index = 0;

    //     while index < proof_chain.len() {
    //         let proof = proof_chain.get(index).unwrap();
    //         let empty_proceeding =
    //             proof.proceeding.is_none() || proof.proceeding.clone().unwrap().is_empty();

    //         // If proceeding isn't empty on base proof we simply flag it as inactive and exit
    //         if index == 0 && !empty_proceeding {
    //             update_entitity.0 = proof.id.unwrap();
    //             update_entitity.1 = true;

    //             // Make loop exit
    //             index = proof_chain.len();
    //         } else {
    //             if empty_proceeding && (index == 0 || proof.inactive.unwrap()) {
    //                 delete_entities.push(proof.id.unwrap());
    //                 // Remove from preceding proof's proceeding vec
    //                 let next_proof = proof_chain.get(index + 1).unwrap();
    //                 let mut next_proceeding = next_proof.proceeding.clone().unwrap();
    //                 let pos = next_proceeding
    //                     .iter()
    //                     .position(|&x| x == proof.id.unwrap())
    //                     .unwrap();

    //                 update_entitity.0 = next_proof.id.unwrap();
    //                 update_entitity.2 = next_proceeding.remove(pos);

    //                 proof_chain[index + 1].proceeding = Some(next_proceeding);
    //                 index += 1;
    //             // When we reach the last inactive proof we can end the loop
    //             } else {
    //                 index = proof_chain.len();
    //             }
    //         }
    //     }

    //     // Delete documents if not empty
    //     if !delete_entities.is_empty() {
    //         let filter = doc! {
    //             "_id": {"$in": delete_entities} // Match documents whose IDs are in the provided list
    //         };
    //         self.degree_proofs
    //             .delete_many(filter, None)
    //             .await
    //             .expect("Error deleting degree proofs");
    //     }

    //     // Update document
    //     let update_filter = doc! {"_id": update_entitity.0};
    //     let update;
    //     if update_entitity.1 {
    //         update = doc! {"$set": { "inactive": true }};
    //     } else {
    //         update = doc! {"$pull": { "proceeding": update_entitity.2 }};
    //     }
    //     self.degree_proofs
    //         .update_one(update_filter, update, None)
    //         .await
    //         .expect("Error updating degree proof");

    //     // create new proof document
    //     let proof_oid = self
    //         .degree_proofs
    //         .insert_one(proof, None)
    //         .await
    //         .unwrap()
    //         .inserted_id
    //         .as_object_id()
    //         .unwrap();

    //     // reference this proof in previous proof if not first proof in chain
    //     if proof.preceding.is_some() {
    //         let query = doc! { "_id": proof.preceding.unwrap() };
    //         let update = doc! { "$push": { "proceeding": bson::to_bson(&proof_oid).unwrap()} };
    //         self.degree_proofs
    //             .update_one(query, update, None)
    //             .await
    //             .unwrap();
    //     }

    //     // push the proof to the user's list of proofs
    //     let query = doc! { "_id": user };
    //     let update = doc! {"$push": { "degree_proofs": bson::to_bson(&proof_oid).unwrap()}};
    //     self.users
    //         .update_one(query.clone(), update, None)
    //         .await
    //         .unwrap();

    //     // If a proof is marked inactive then remove from user's list of degree proofs
    //     if update_entitity.1 {
    //         let update = doc! { "$pull": { "degree_proofs": update_entitity.0 } };
    //         self.users.update_one(query, update, None).await.unwrap();
    //     }
    //     Ok(proof_oid)
    // }

    // // pub async fn get_proof(&self, proof_oid: &ObjectId) -> Option<DegreeProof> {
    // //     self.degree_proofs
    // //         .find_one(doc! { "_id": proof_oid }, None)
    // //         .await
    // //         .unwrap()
    // // }

    // // pub async fn remove_user(&self, user: &ObjectId) {
    // //     self.users
    // //         .delete_one(doc! { "_id": user }, None)
    // //         .await
    // //         .expect("Failed to remove user");
    // // }

    // /**
    //  * Given a user, find available degrees of separation proofs they can build from
    //  *   - find degree chains they are not a part of
    //  *   - find lower degree proofs they can build from
    //  */
    // pub async fn find_available_degrees(&self, username: String) -> Vec<String> {
    //     // find degree chains they are not a part of
    //     let pipeline = vec![
    //         // find the user to find available proofs for
    //         doc! { "$match": { "username": username } },
    //         doc! { "$project": { "relationships": 1, "degree_proofs": 1, "_id": 0 } },
    //         // look up the degree proofs made by this user
    //         doc! {
    //             "$lookup": {
    //                 "from": "degree_proofs",
    //                 "localField": "degree_proofs",
    //                 "foreignField": "_id",
    //                 "as": "userDegreeProofs",
    //                 "pipeline": [doc! { "$project": { "degree": 1, "phrase": 1 } }]
    //             }
    //         },
    //         // look up the relationships made by this user
    //         doc! {
    //             "$lookup": {
    //                 "from": "relationships",
    //                 "localField": "relationships",
    //                 "foreignField": "_id",
    //                 "as": "userRelationships",
    //                 "pipeline": [doc! { "$project": { "sender": 1 } }]
    //             }
    //         },
    //         // look up the degree proofs made by relationships
    //         // @todo: allow limitation of degrees of separation here
    //         doc! {
    //             "$lookup": {
    //                 "from": "degree_proofs",
    //                 "localField": "userRelationships.sender",
    //                 "foreignField": "user",
    //                 "as": "relationshipDegreeProofs",
    //                 "pipeline": [
    //                     doc! { "$match": { "inactive": { "$ne": true } } },
    //                     doc! { "$project": { "degree": 1, "phrase": 1 } }
    //                 ]
    //             }
    //         },
    //         // unwind the results
    //         doc! { "$project": { "userDegreeProofs": 1, "relationshipDegreeProofs": 1 } },
    //         doc! { "$unwind": "$relationshipDegreeProofs" },
    //         // find the lowest degree proof in each chain from relationship proofs and reference user proofs in this chain if exists
    //         doc! {
    //             "$group": {
    //                 "_id": "$relationshipDegreeProofs.phrase",
    //                 "originalId": { "$first": "$relationshipDegreeProofs._id" },
    //                 "degree": { "$min": "$relationshipDegreeProofs.degree" },
    //                 "userProof": {
    //                     "$first": {
    //                         "$arrayElemAt": [{
    //                             "$filter": {
    //                                 "input": "$userDegreeProofs",
    //                                 "as": "userProof",
    //                                 "cond": { "$eq": ["$$userProof.phrase", "$relationshipDegreeProofs.phrase"] }
    //                             }
    //                         }, 0]
    //                     }
    //                 }
    //             }
    //         },
    //         // remove the proofs that do not offer improved degrees of separation from existing user proofs
    //         doc! {
    //             "$match": {
    //                 "$expr": {
    //                     "$or": [
    //                         { "$gte": ["$userProof.degree", { "$add": ["$degree", 2] }] },
    //                         { "$eq": ["$userProof", null] }
    //                     ]
    //                 }
    //             }
    //         },
    //         // project only the ids of the proofs the user can build from
    //         doc! { "$project": { "_id": "$originalId" } },
    //     ];
    //     // get the OID's of degree proofs the user can build from
    //     let mut proofs: Vec<String> = vec![];
    //     let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
    //     while let Some(result) = cursor.next().await {
    //         match result {
    //             Ok(document) => {
    //                 let oid = document
    //                     .get("_id")
    //                     .and_then(|id| id.as_object_id())
    //                     .unwrap();
    //                 proofs.push(oid.to_string());
    //             }
    //             Err(e) => println!("Error: {}", e),
    //         }
    //     }

    //     proofs
    // }

    // /**
    //  * Get all degree proofs created by a specific user
    //  */
    // pub async fn get_known(&self, username: String) -> Option<Vec<DegreeData>> {
    //     let pipeline = vec![
    //         // Step 1: Find the user by username to get their degree proofs
    //         doc! { "$match": { "username": username } },
    //         doc! { "$project": { "_id": 1, "degree_proofs": 1 } },
    //         // Step 2: Look up degree proofs by this user of degree 1
    //         doc! {
    //             "$lookup": {
    //                 "from": "degree_proofs",
    //                 "localField": "degree_proofs",
    //                 "foreignField": "_id",
    //                 "as": "proofs",
    //                 "pipeline": [
    //                     { "$match": { "$expr": { "$eq": ["$degree", 1] } } }, // Note: Adjusted to use a static value for "degree"
    //                     { "$project": { "degree": 1, "ciphertext": 1, "phrase": 1 } }
    //                 ]
    //             }
    //         },
    //         doc! { "$unwind": "$proofs" },
    //         // Step 3: Cross reference the phrase documents to get auxiliary phrase information
    //         doc! {
    //             "$lookup": {
    //                 "from": "phrases",
    //                 "localField": "proofs.phrase",
    //                 "foreignField": "_id",
    //                 "as": "phrase",
    //             }
    //         },
    //         doc! { "$unwind": "$phrase" },
    //         // Step 4: Prune unnecessary fields and return the result
    //         doc! {
    //             "$project": {
    //                 "hash": "$phrase.hash",
    //                 "index": "$phrase.index",
    //                 "description": "$phrase.description",
    //                 "ciphertext": "$proofs.ciphertext",
    //             }
    //         },
    //     ];
    //     // get the OID's of degree proofs the user can build from
    //     let mut degrees: Vec<DegreeData> = vec![];
    //     let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
    //     while let Some(result) = cursor.next().await {
    //         match result {
    //             Ok(document) => {
    //                 let phrase_hash: [u8; 32] = document
    //                     .get("hash")
    //                     .unwrap()
    //                     .as_array()
    //                     .unwrap()
    //                     .iter()
    //                     .map(|x| x.as_i32().unwrap() as u8)
    //                     .collect::<Vec<u8>>()
    //                     .try_into()
    //                     .unwrap();
    //                 let mut secret_phrase: Option<[u8; 192]> = None;
    //                 if let Some(Bson::Binary(binary)) = document.get("ciphertext") {
    //                     secret_phrase = Some(binary.bytes.clone().try_into().unwrap());
    //                 }
    //                 let phrase_index = document.get("index").unwrap().as_i64().unwrap() as u32;
    //                 let description = document
    //                     .get("description")
    //                     .unwrap()
    //                     .as_str()
    //                     .unwrap()
    //                     .to_string();
    //                 degrees.push(DegreeData {
    //                     description,
    //                     degree: Some(1),
    //                     phrase_index,
    //                     relation: None,
    //                     preceding_relation: None,
    //                     phrase_hash,
    //                     secret_phrase,
    //                 });
    //             }
    //             Err(e) => {
    //                 println!("Error: {}", e);
    //                 return None;
    //             }
    //         }
    //     }
    //     Some(degrees)
    // }

    // // @todo: ask chatgpt for better name
    // pub async fn get_all_degrees(&self, username: String) -> Option<Vec<DegreeData>> {
    //     let pipeline = vec![
    //         // get the user to find the proofs of degrees of separation for the user
    //         doc! { "$match": { "username": username } },
    //         doc! { "$project": { "_id": 1, "degree_proofs": 1 } },
    //         // look up the degree proof documents
    //         doc! {
    //             "$lookup": {
    //                 "from": "degree_proofs",
    //                 "localField": "degree_proofs",
    //                 "foreignField": "_id",
    //                 "as": "proofs",
    //                 "pipeline": [doc! { "$project": { "degree": 1, "preceding": 1, "phrase": 1 } }]
    //             }
    //         },
    //         doc! {
    //             "$project": {
    //                 "proofs": {
    //                     "$filter": {
    //                       "input": "$proofs",
    //                       "as": "proof",
    //                       "cond": { "$gt": ["$$proof.degree", 1] }
    //                     }
    //                 },
    //             }
    //         },
    //         doc! { "$unwind": "$proofs" },
    //         doc! {
    //             "$project": {
    //                 "degree": "$proofs.degree",
    //                 "preceding": "$proofs.preceding",
    //                 "phrase": "$proofs.phrase",
    //                 "_id": 0
    //             }
    //         },
    //         // get the preceding proof if it exists, then get the user who made it to show the connection
    //         doc! {
    //             "$lookup": {
    //                 "from": "degree_proofs",
    //                 "localField": "preceding",
    //                 "foreignField": "_id",
    //                 "as": "relation",
    //                 "pipeline": [doc! { "$project": { "preceding": 1, "user": 1, "_id": 0 } }]
    //             }
    //         },
    //         doc! {
    //             "$project": {
    //                 "degree": 1,
    //                 "preceding": 1,
    //                 "phrase": 1,
    //                 "relation": { "$arrayElemAt": ["$relation.user", 0] },
    //                 "precedingRelation": { "$arrayElemAt": ["$relation.preceding", 0] },
    //                 "_id": 0
    //             }
    //         },
    //         doc! {
    //             "$lookup": {
    //                 "from": "users",
    //                 "localField": "relation",
    //                 "foreignField": "_id",
    //                 "as": "relation",
    //                 "pipeline": [doc! { "$project": { "_id": 0, "username": 1 } }]
    //             }
    //         },
    //         doc! {
    //             "$project": {
    //                 "degree": 1,
    //                 "phrase": 1,
    //                 "relation": { "$arrayElemAt": ["$relation.username", 0] },
    //                 "precedingRelation": 1,
    //                 "_id": 0
    //             }
    //         },
    //         // Lookup preceding relation. Will be none if degree is 2 or less
    //         doc! {
    //           "$lookup": {
    //             "from": "degree_proofs",
    //             "localField": "precedingRelation",
    //             "foreignField": "_id",
    //             "as": "precedingRelation",
    //             "pipeline": [doc! { "$project": { "user": 1, "_id": 0 } }]
    //           },
    //         },
    //         doc! {
    //             "$project": {
    //                 "degree": 1,
    //                 "phrase": 1,
    //                 "relation": 1,
    //                 "precedingRelation": { "$arrayElemAt": ["$precedingRelation.user", 0] },
    //             }
    //         },
    //         doc! {
    //             "$lookup": {
    //                 "from": "users",
    //                 "localField": "precedingRelation",
    //                 "foreignField": "_id",
    //                 "as": "precedingRelation",
    //                 "pipeline": [doc! { "$project": { "_id": 0, "username": 1 } }]
    //             }
    //         },
    //         doc! {
    //             "$project": {
    //                 "degree": 1,
    //                 "phrase": 1,
    //                 "relation": 1,
    //                 "precedingRelation": { "$arrayElemAt": ["$precedingRelation.username", 0] },
    //                 "_id": 0
    //             }
    //         },
    //         doc! {
    //             "$lookup": {
    //                 "from": "phrases",
    //                 "localField": "phrase",
    //                 "foreignField": "_id",
    //                 "as": "phrase",
    //                 "pipeline": [doc! { "$project": { "index": 1, "hash": 1, "description": 1, "_id": 0 } }]
    //             }
    //         },
    //         doc! {
    //             "$unwind": "$phrase"
    //         },
    //         doc! {
    //             "$set": {
    //                 "phrase_index": "$phrase.index",
    //                 "phrase_hash": "$phrase.hash",
    //                 "phrase_description": "$phrase.description"
    //             }
    //         },
    //         doc! {
    //             "$project": {
    //                 "phrase": 0
    //             }
    //         },
    //         doc! { "$sort": { "degree": 1 }},
    //     ];
    //     // get the OID's of degree proofs the user can build from
    //     let mut degrees: Vec<DegreeData> = vec![];
    //     let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
    //     while let Some(result) = cursor.next().await {
    //         match result {
    //             Ok(document) => {
    //                 let degree = document.get_i32("degree").unwrap() as u8;
    //                 let relation = document
    //                     .get("relation")
    //                     .unwrap()
    //                     .as_str()
    //                     .unwrap()
    //                     .to_string();
    //                 let preceding_relation = match document.get("precedingRelation") {
    //                     Some(relation) => Some(relation.as_str().unwrap().to_string()),
    //                     None => None,
    //                 };
    //                 // @todo: can this be retrieved better?
    //                 let phrase_hash: [u8; 32] = document
    //                     .get("phrase_hash")
    //                     .unwrap()
    //                     .as_array()
    //                     .unwrap()
    //                     .iter()
    //                     .map(|x| x.as_i32().unwrap() as u8)
    //                     .collect::<Vec<u8>>()
    //                     .try_into()
    //                     .unwrap();
    //                 let phrase_index = document.get_i64("phrase_index").unwrap() as u32;
    //                 let phrase_description = document
    //                     .get("phrase_description")
    //                     .unwrap()
    //                     .as_str()
    //                     .unwrap()
    //                     .to_string();
    //                 degrees.push(DegreeData {
    //                     description: phrase_description,
    //                     degree: Some(degree),
    //                     phrase_index,
    //                     relation: Some(relation),
    //                     preceding_relation,
    //                     phrase_hash,
    //                     secret_phrase: None,
    //                 });
    //             }
    //             Err(e) => {
    //                 println!("Error: {}", e);
    //                 return None;
    //             }
    //         }
    //     }
    //     Some(degrees)
    // }

    // /**
    //  * Get a proof from the server with all info needed to prove a degree of separation as a given user
    //  *
    //  * @param username - the username of the user proving a degree of separation
    //  * @param oid - the id of the proof to get
    //  */
    // pub async fn get_proof_and_data(
    //     &self,
    //     username: String,
    //     proof: ObjectId,
    // ) -> Option<ProvingData> {
    //     // @todo: aggregation pipeline
    //     // get the proof
    //     let filter = doc! { "_id": proof };
    //     let projection = doc! { "user": 1, "degree": 1, "proof": 1, "phrase": 1 };
    //     let find_options = FindOneOptions::builder().projection(projection).build();
    //     let proof = self
    //         .degree_proofs
    //         .find_one(filter, Some(find_options))
    //         .await
    //         .unwrap()
    //         .unwrap();
    //     // look up the phrase info
    //     let filter = doc! { "_id": proof.phrase.unwrap() };
    //     let projection = doc! { "index": 1, "hash": 1, "description": 1 };
    //     let find_options = FindOneOptions::builder().projection(projection).build();
    //     let phrase = self
    //         .phrases
    //         .find_one(filter, Some(find_options))
    //         .await
    //         .unwrap()
    //         .unwrap();
    //     // get the username of the user who made the proof
    //     let proof_creator = proof.user.unwrap();
    //     let filter = doc! { "_id": proof_creator };
    //     let projection = doc! { "username": 1, "pubkey": 1 };
    //     let find_options = FindOneOptions::builder().projection(projection).build();
    //     let proof_creator_username = self
    //         .users
    //         .find_one(filter, Some(find_options))
    //         .await
    //         .unwrap()
    //         .unwrap()
    //         .username
    //         .unwrap();
    //     // get the oid of message sender
    //     let filter = doc! { "username": username };
    //     let projection = doc! { "_id": 1, "pubkey": 1 };
    //     let find_options = FindOneOptions::builder().projection(projection).build();
    //     let caller = self
    //         .users
    //         .find_one(filter, Some(find_options))
    //         .await
    //         .unwrap()
    //         .unwrap()
    //         .id
    //         .unwrap();
    //     // look up relationship with sender and recipient
    //     let filter = doc! { "sender": proof_creator, "recipient": caller };
    //     let projection = doc! { "ephemeral_key": 1, "ciphertext": 1};
    //     let find_options = FindOneOptions::builder().projection(projection).build();
    //     let relationship = self
    //         .relationships
    //         .find_one(filter, Some(find_options))
    //         .await
    //         .unwrap()
    //         .unwrap();

    //     // return the proof data
    //     Some(ProvingData {
    //         description: phrase.description.unwrap(),
    //         phrase_index: phrase.index.unwrap(),
    //         phrase_hash: phrase.hash.unwrap(),
    //         degree: proof.degree.unwrap(),
    //         proof: proof.proof.unwrap(),
    //         username: proof_creator_username,
    //         ephemeral_key: relationship.ephemeral_key.unwrap(),
    //         ciphertext: relationship.ciphertext.unwrap(),
    //     })
    // }

    // /**
    // * Get details on account:
    //    - # of first degree connections
    //    - # of second degree connections
    //    - # of phrases created
    // */
    // pub async fn get_account_details(&self, user: &ObjectId) -> Option<(u64, u64, u64)> {
    //     let mut cursor = self
    //         .users
    //         .aggregate(
    //             vec![
    //                 doc! {
    //                   "$match": {
    //                     "_id": user
    //                   }
    //                 },
    //                 // Lookup to join with the relationships collection
    //                 doc! {
    //                     "$lookup": {
    //                         "from": "relationships",
    //                         "localField": "relationships",
    //                         "foreignField": "_id",
    //                         "as": "relationships_data",
    //                         "pipeline": [doc! { "$project": { "_id": 0, "sender": 1 } }]
    //                     }
    //                 },
    //                 // Add sender values to first degree connection array
    //                 doc! {
    //                     "$addFields": {
    //                         "first_degree_connections": {
    //                             "$map": {
    //                                 "input": "$relationships_data",
    //                                 "as": "relationship",
    //                                 "in": "$$relationship.sender"
    //                             }
    //                         }
    //                     }
    //                 },
    //                 // Lookup first degree connection senders from users colection
    //                 doc! {
    //                     "$lookup": {
    //                         "from": "users",
    //                         "localField": "first_degree_connections",
    //                         "foreignField": "_id",
    //                         "as": "sender_relationships"
    //                     }
    //                 },
    //                 doc! {
    //                     "$unwind": {
    //                         "path": "$sender_relationships",
    //                         "preserveNullAndEmptyArrays": true
    //                     }
    //                 },
    //                 doc! {
    //                     "$lookup": {
    //                         "from": "relationships",
    //                         "localField": "sender_relationships.relationships",
    //                         "foreignField": "_id",
    //                         "as": "sender_relationships.relationships_data"
    //                     }
    //                 },
    //                 doc! {
    //                     "$group": {
    //                         "_id": "$_id",
    //                         "first_degree_connections": { "$first": "$first_degree_connections" },
    //                         "sender_relationships": { "$push": "$sender_relationships" }
    //                     }
    //                 },
    //                 doc! {
    //                     "$addFields": {
    //                         "second_degree_connections": {
    //                             "$cond": {
    //                                 "if": { "$eq": [ "$sender_relationships", [] ] },
    //                                 "then": [],
    //                                 "else": {
    //                                     "$reduce": {
    //                                         "input": "$sender_relationships",
    //                                         "initialValue": [],
    //                                         "in": {
    //                                             "$concatArrays": [
    //                                                 "$$value",
    //                                                 {
    //                                                     "$filter": {
    //                                                         "input": {
    //                                                             "$map": {
    //                                                                 "input": "$$this.relationships_data",
    //                                                                 "as": "relationship",
    //                                                                 "in": {
    //                                                                     "$cond": [
    //                                                                         {
    //                                                                             "$and": [
    //                                                                                 { "$ne": [ "$$relationship.sender", null ] },
    //                                                                                 { "$ne": [ "$$relationship.sender", user ] },
    //                                                                                 { "$not": { "$in": [ "$$relationship.sender", "$first_degree_connections" ] } },
    //                                                                                 { "$not": { "$in": [ "$$relationship.sender", "$$value" ] } }
    //                                                                             ]
    //                                                                         },
    //                                                                         "$$relationship.sender",
    //                                                                         null
    //                                                                     ]
    //                                                                 }
    //                                                             }
    //                                                         },
    //                                                         "cond": { "$ne": [ "$$this", null ] }
    //                                                     }
    //                                                 }
    //                                             ]
    //                                         }
    //                                     }
    //                                 }
    //                             }
    //                         }
    //                     }
    //                 },
    //                 doc! {
    //                     "$addFields": {
    //                         "second_degree_connections": {
    //                             "$setUnion": ["$second_degree_connections", []]
    //                         }
    //                     }
    //                 },
    //                 doc! {
    //                     "$lookup": {
    //                         "from": "degree_proofs",
    //                         "localField": "_id",
    //                         "foreignField": "user",
    //                         "as": "user_degrees"
    //                     }
    //                 },
    //                 doc! {
    //                     "$addFields": {
    //                         "phrase_count": {
    //                             "$size": {
    //                                 "$filter": {
    //                                     "input": "$user_degrees",
    //                                     "as": "degree",
    //                                     "cond": { "$eq": ["$$degree.degree", 1] }
    //                                 }
    //                             }
    //                         }
    //                     }
    //                 },
    //                 doc! {
    //                     "$project": {
    //                         "phrase_count": 1,
    //                         "first_degree_connections": { "$size": "$first_degree_connections" },
    //                         "second_degree_connections": { "$size": "$second_degree_connections" },
    //                         "second_degree_connections_all":  "$second_degree_connections",
    //                         "first_degree_connections_all":  "$first_degree_connections"
    //                     }
    //                 }
    //             ],
    //             None,
    //         )
    //         .await
    //         .unwrap();

    //     match cursor.next().await.unwrap() {
    //         Ok(stats) => {
    //             let phrase_count = stats.get_i32("phrase_count").unwrap();
    //             let first_degree_connections = stats.get_i32("first_degree_connections").unwrap();
    //             let second_degree_connections = stats.get_i32("second_degree_connections").unwrap();
    //             return Some((
    //                 phrase_count as u64,
    //                 first_degree_connections as u64,
    //                 second_degree_connections as u64,
    //             ));
    //         }
    //         Err(e) => {
    //             println!("Error: {:?}", e);
    //             return None;
    //         }
    //     }
    // }

    // /**
    //  * Get chain of degree proofs linked to a phrase
    //  *
    //  * @param phrase_hash - hash of the phrase linking the proof chain together
    //  */
    // pub async fn get_phrase_connections(
    //     &self,
    //     username: String,
    //     phrase_index: u32,
    // ) -> Option<(u64, Vec<u64>)> {
    //     let mut cursor = self
    //         .users
    //         .aggregate(
    //             vec![
    //                 // Step 1: get relationships of the user
    //                 doc! { "$match": { "username": username } },
    //                 doc! { "$unwind": "$relationships" },
    //                 doc! {
    //                     "$lookup": {
    //                         "from": "relationships",
    //                         "localField": "relationships",
    //                         "foreignField": "_id",
    //                         "as": "relationship_details"
    //                     }
    //                 },
    //                 doc! {
    //                     "$unwind": "$relationship_details"
    //                 },
    //                 // step 2: ensure unique senders
    //                 doc! {
    //                     "$group": {
    //                         "_id": null,
    //                         "senders": {
    //                             "$addToSet": "$relationship_details.sender"
    //                         }
    //                     }
    //                 },
    //                 doc! { "$project": { "_id": 0, "senders": 1 } },
    //                 // step 3: look up the phrase document by index
    //                 doc! {
    //                     "$lookup": {
    //                         "from": "phrases",
    //                         "let": { "index": phrase_index },
    //                         "pipeline": [
    //                             { "$match": { "$expr": { "$eq": ["$index", "$$index"] } } },
    //                             { "$project": { "_id": 1 } }
    //                         ],
    //                         "as": "phrase_document"
    //                     }
    //                 },
    //                 doc! { "$unwind": "$phrase_document" },
    //                 // step 4: find all active degree proofs for the phrase made by relationships
    //                 doc! {
    //                     "$lookup": {
    //                         "from": "degree_proofs",
    //                         "let": { "senders": "$senders", "phrase": "$phrase_document._id" },
    //                         "pipeline": [
    //                             {
    //                                 "$match": {
    //                                     "$expr": {
    //                                         "$and": [
    //                                             { "$in": ["$user", "$$senders"] },
    //                                             { "$eq": ["$phrase", "$$phrase"] },
    //                                             { "$ne": ["$inactive", true] }
    //                                         ]
    //                                     }
    //                                 }
    //                             },
    //                             { "$project": { "_id": 0, "degree": 1 } }
    //                         ],
    //                         "as": "degree_proofs"
    //                     }
    //                 },
    //                 doc! { "$unwind": "$degree_proofs" },
    //                 doc! {
    //                     "$group": {
    //                         "_id": null,
    //                         "max_degree": { "$max": "$degree_proofs.degree" },
    //                         "count": { "$sum": 1 },
    //                         "degrees": { "$push": "$degree_proofs.degree" }
    //                     }
    //                 },
    //             ],
    //             None,
    //         )
    //         .await
    //         .unwrap();

    //     let cursor_res = cursor.next().await;

    //     if cursor_res.is_none() {
    //         return Some((0, vec![]));
    //     }

    //     match cursor_res.unwrap() {
    //         Ok(connection_data) => {
    //             let total_count = connection_data.get_i32("count").unwrap();
    //             let max_degree = connection_data.get_i32("max_degree").unwrap();
    //             let mut degree_counts: Vec<u64> = vec![0; max_degree as usize];
    //             let degrees: Vec<i32> = connection_data
    //                 .get_array("degrees")
    //                 .unwrap()
    //                 .iter()
    //                 .map(|d| d.as_i32().unwrap())
    //                 .collect();
    //             for degree in degrees {
    //                 degree_counts[(degree - 1) as usize] += 1;
    //             }
    //             return Some((total_count as u64, degree_counts));
    //         }
    //         Err(e) => {
    //             println!("Error: {:?}", e);
    //             return None;
    //         }
    //     }
    // }

    // /**
    //  * Check to see if degree already exists between two accounts
    //  *
    //  * @param proof - Degree proof to be inserted
    //  */
    // pub async fn check_degree_exists(&self, proof: &DegreeProof) -> Result<bool, GrapevineError> {
    //     let query = doc! {"preceding": proof.preceding.unwrap(), "user": proof.user.unwrap()};
    //     let projection = doc! { "_id": 1 };
    //     let find_options = FindOneOptions::builder().projection(projection).build();

    //     match self.degree_proofs.find_one(query, find_options).await {
    //         Ok(res) => Ok(res.is_some()),
    //         Err(e) => Err(GrapevineError::MongoError(e.to_string())),
    //     }
    // }

    // /**
    //  * Check to see if phrase hash already exists
    //  *
    //  * @param phrase_hash - hash of the phrase linking the proof
    //  */
    // pub async fn get_phrase_by_hash(
    //     &self,
    //     phrase_hash: &[u8; 32],
    // ) -> Result<ObjectId, GrapevineError> {
    //     let phrase_hash_bson: Vec<i32> = phrase_hash.to_vec().iter().map(|x| *x as i32).collect();

    //     let query = doc! {"hash": phrase_hash_bson};
    //     let projection = doc! { "_id": 1 };
    //     let find_options = FindOneOptions::builder().projection(projection).build();

    //     match self.phrases.find_one(query, find_options).await {
    //         Ok(res) => match res {
    //             Some(document) => Ok(document.id.unwrap()),
    //             None => Err(GrapevineError::PhraseNotFound),
    //         },
    //         Err(e) => Err(GrapevineError::MongoError(e.to_string())),
    //     }
    // }

    // /**
    //  * Return the oid of a phrase given its index
    //  *
    //  * @param index - index of the phrase
    //  * @return - ObjectId of the phrase if it exists
    //  */
    // pub async fn get_phrase_by_index(&self, index: u32) -> Result<ObjectId, GrapevineError> {
    //     let options = FindOneOptions::builder()
    //         .projection(doc! { "_id": 1 })
    //         .build();
    //     match self.phrases.find_one(doc! {"index": index}, options).await {
    //         Ok(res) => match res {
    //             Some(document) => Ok(document.id.unwrap()),
    //             None => Err(GrapevineError::PhraseNotFound),
    //         },
    //         Err(e) => Err(GrapevineError::MongoError(e.to_string())),
    //     }
    // }

    // /**
    //  * Checks to see whether the user has already created a degree proof for the phrase
    //  *
    //  * @param user - the username of the user to check for
    //  * @param phrase_index - the index of the phrase to check for
    //  * @degree - the degree of the proof to check for
    //  * @return - true if a degree proof was found matching the user, index, and degree, and false otherwise
    //  */
    // pub async fn check_degree_conflict(
    //     &self,
    //     user: &String,
    //     phrase_index: u32,
    //     degree: u8,
    // ) -> Result<bool, GrapevineError> {
    //     let mut cursor = self
    //         .users
    //         .aggregate(
    //             vec![
    //                 // Step 1: retrieve the ID of the user using the username
    //                 doc! { "$match": { "username": user } },
    //                 // Step 2: retrieve the ID of the phrase using the phrase index
    //                 doc! {
    //                     "$lookup": {
    //                         "from": "phrases",
    //                         "let": {
    //                             "index": phrase_index,
    //                         },
    //                         "pipeline": [
    //                             { "$match": { "$expr": { "$eq": ["$index", "$$index"] } } },
    //                             { "$project": { "_id": 1 } }
    //                         ],
    //                         "as": "phrases"
    //                     }
    //                 },
    //                 doc! { "$unwind": "$phrases" },
    //                 // Step 3: retrieve any degree proofs that match the user, phrase, and degree
    //                 doc! {
    //                     "$lookup": {
    //                         "from": "degree_proofs",
    //                         "let": {
    //                             "phrase": "$phrases._id",
    //                             "user": "$_id",
    //                             "degree": degree as i64,
    //                         },
    //                         "pipeline": [
    //                             {
    //                                 "$match": {
    //                                     "$expr": {
    //                                         "$and": [
    //                                             { "$eq": ["$phrase", "$$phrase"] },
    //                                             { "$eq": ["$user", "$$user"] },
    //                                             { "$eq": ["$degree", "$$degree"] }
    //                                         ]
    //                                     }
    //                                 }
    //                             },
    //                             { "$project": { "_id": 1 } }
    //                         ],
    //                         "as": "degree_proofs"
    //                     }
    //                 },
    //                 doc! { "$unwind": "$degree_proofs" },
    //                 doc! { "$project": { "_id": "$phrases._id" } },
    //             ],
    //             None,
    //         )
    //         .await
    //         .unwrap();

    //     let cursor_res = cursor.next().await;
    //     return match cursor_res {
    //         Some(Ok(_)) => Ok(true),
    //         Some(Err(e)) => Err(GrapevineError::MongoError(e.to_string())),
    //         None => Ok(false),
    //     };
    // }

    // pub async fn get_phrase_index(&self, oid: &ObjectId) -> Result<u32, GrapevineError> {
    //     let options = FindOneOptions::builder()
    //         .projection(doc! { "index": 1 })
    //         .build();
    //     match self.phrases.find_one(doc! {"_id": oid}, options).await {
    //         Ok(res) => match res {
    //             Some(document) => Ok(document.index.unwrap()),
    //             None => Err(GrapevineError::PhraseNotFound),
    //         },
    //         Err(e) => Err(GrapevineError::MongoError(e.to_string())),
    //     }
    // }

    // /**
    //  * Returns all info about a phrase known to a given user
    //  * @notice: connections done separately
    //  *
    //  * @param username - the username of the user
    //  * @param index - the index of the phrase
    //  *
    //  * @returns
    //  */
    // pub async fn get_phrase_info(
    //     &self,
    //     username: &String,
    //     index: u32,
    // ) -> Result<DegreeData, GrapevineError> {
    //     // find the degree data for a given proof
    //     let pipeline = vec![
    //         // look up the user by username
    //         doc! { "$match": { "username": username } },
    //         doc! { "$project": { "_id": 1 } },
    //         // look up the phrase by index
    //         doc! {
    //             "$lookup": {
    //                 "from": "phrases",
    //                 "let": { "index": index as i64 },
    //                 "as": "phrase",
    //                 "pipeline": [
    //                     doc! { "$match": { "$expr": { "$eq": ["$index", "$$index"] } } },
    //                 ]
    //             }
    //         },
    //         doc! { "$unwind": "$phrase" },
    //         // search for an active degree proof matching the phrase and user
    //         doc! {
    //             "$lookup": {
    //                 "from": "degree_proofs",
    //                 "let": { "user": "$_id", "phrase": "$phrase._id" },
    //                 "as": "proof",
    //                 "pipeline": [
    //                     doc! {
    //                         "$match": {
    //                             "$expr": {
    //                                 "$and": [
    //                                     { "$eq": ["$user", "$$user"] },
    //                                     { "$eq": ["$phrase", "$$phrase"] },
    //                                     { "$eq": ["$inactive", false] }
    //                                 ]
    //                             }
    //                         }
    //                     },
    //                     doc! { "$project": { "degree": 1, "preceding": 1, "phrase": 1, "ciphertext": 1 } }
    //                 ]
    //             }
    //         },
    //         doc! {
    //             "$unwind": {
    //                 "path": "$proof",
    //                 "preserveNullAndEmptyArrays": true
    //             }
    //         },
    //         // search for a degree proof preceding the user's proof (degree 1 from user)
    //         doc! {
    //             "$lookup": {
    //                 "from": "degree_proofs",
    //                 "localField": "proof.preceding",
    //                 "foreignField": "_id",
    //                 "as": "degree_1",
    //                 "pipeline": [doc! { "$project": { "preceding": 1, "user": 1, "_id": 0 } }]
    //             }
    //         },
    //         doc! {
    //             "$unwind": {
    //                 "path": "$degree_1",
    //                 "preserveNullAndEmptyArrays": true
    //             }
    //         },
    //         // search for a degree proof preceding the proof that is 1 degree from the user's proof (degree 2 from user)
    //         doc! {
    //             "$lookup": {
    //                 "from": "degree_proofs",
    //                 "localField": "degree_1.preceding",
    //                 "foreignField": "_id",
    //                 "as": "degree_2",
    //                 "pipeline": [doc! { "$project": { "user": 1, "_id": 0 } }]
    //             }
    //         },
    //         doc! {
    //             "$unwind": {
    //                 "path": "$degree_2",
    //                 "preserveNullAndEmptyArrays": true
    //             }
    //         },
    //         // convert the 1st and 2nd degree relations into usernames
    //         doc! {
    //             "$lookup": {
    //                 "from": "users",
    //                 "localField": "degree_1.user",
    //                 "foreignField": "_id",
    //                 "as": "degree_1",
    //                 "pipeline": [doc! { "$project": { "username": 1, "_id": 0 } }]
    //             }
    //         },
    //         doc! {
    //             "$unwind": {
    //                 "path": "$degree_1",
    //                 "preserveNullAndEmptyArrays": true
    //             }
    //         },
    //         doc! {
    //             "$lookup": {
    //                 "from": "users",
    //                 "localField": "degree_2.user",
    //                 "foreignField": "_id",
    //                 "as": "degree_2",
    //                 "pipeline": [doc! { "$project": { "username": 1, "_id": 0 } }]
    //             }
    //         },
    //         doc! {
    //             "$unwind": {
    //                 "path": "$degree_2",
    //                 "preserveNullAndEmptyArrays": true
    //             }
    //         },
    //         // project the final results
    //         doc! {
    //             "$project": {
    //                 "hash": "$phrase.hash",
    //                 "description": "$phrase.description",
    //                 "degree": "$proof.degree",
    //                 "ciphertext": "$proof.ciphertext",
    //                 "degree_1": "$degree_1.username",
    //                 "degree_2": "$degree_2.username",
    //                 "_id": 0
    //             }
    //         },
    //     ];
    //     let mut cursor = self.users.aggregate(pipeline, None).await.unwrap();
    //     if let Some(result) = cursor.next().await {
    //         match result {
    //             Ok(document) => {
    //                 println!("Document: {:#?}", document);
    //                 // get the degree of separation found for this user on this phrase
    //                 let degree = match document.get_i32("degree") {
    //                     Ok(val) => Some(val as u8),
    //                     Err(_) => None,
    //                 };
    //                 println!("Degree: {:?}", degree);
    //                 // get any 1st and 2nd degree relations found for this user on this phrase
    //                 let relation = match document.get("degree_1") {
    //                     Some(degree_1) => Some(degree_1.as_str().unwrap().to_string()),
    //                     None => None,
    //                 };
    //                 println!("Relation: {:?}", relation);
    //                 let preceding_relation = match document.get("degree_2") {
    //                     Some(degree_2) => Some(degree_2.as_str().unwrap().to_string()),
    //                     None => None,
    //                 };
    //                 println!("Preceding relation: {:?}", preceding_relation);
    //                 // get the hash of the phrase
    //                 let phrase_hash: [u8; 32] = document
    //                     .get("hash")
    //                     .unwrap()
    //                     .as_array()
    //                     .unwrap()
    //                     .iter()
    //                     .map(|x| x.as_i32().unwrap() as u8)
    //                     .collect::<Vec<u8>>()
    //                     .try_into()
    //                     .unwrap();
    //                 println!("Phrase hash: {:?}", phrase_hash);
    //                 // get the description of the phrase
    //                 let phrase_description = document
    //                     .get("description")
    //                     .unwrap()
    //                     .as_str()
    //                     .unwrap()
    //                     .to_string();
    //                 println!("Phrase description: {:?}", phrase_description);
    //                 // get the ciphertext of the proof
    //                 let mut secret_phrase: Option<[u8; 192]> = None;
    //                 if let Some(Bson::Binary(binary)) = document.get("ciphertext") {
    //                     secret_phrase = Some(binary.bytes.clone().try_into().unwrap());
    //                 }
    //                 println!("Secret phrase: {:?}", secret_phrase);
    //                 return Ok(DegreeData {
    //                     description: phrase_description,
    //                     degree,
    //                     phrase_index: index,
    //                     relation,
    //                     preceding_relation,
    //                     phrase_hash,
    //                     secret_phrase,
    //                 });
    //             }
    //             Err(_) => {
    //                 return Err(GrapevineError::MongoError(
    //                     "Failed phrase data retrieval".to_string(),
    //                 ));
    //             }
    //         }
    //     } else {
    //         return Err(GrapevineError::MongoError(
    //             "Failed phrase data retrieval".to_string(),
    //         ));
    //     }
    // }
}
