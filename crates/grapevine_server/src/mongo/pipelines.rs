use crate::utils::ToBson;
use mongodb::bson::{doc, oid::ObjectId, Bson, Document};

/**
 * Query for getting first and second degree connection details
 *
 * @param user: the username of the user to query the collection for degrees
 * @returns the aggregation pipeline needed to retrieve the data from mongo
 */
pub fn count_degrees(user: &String) -> Vec<Document> {
    vec![
        // 1. Look up the user doc by OID
        doc! {
            "$match": { "username": user }
        },
        // 2. Look up all active (and non-nullified) relationships where the sender is the recipient
        doc! {
            "$lookup": {
                "from": "relationships",
                "localField": "_id",
                "foreignField": "recipient",
                "as": "first_degree_connections",
                "pipeline": [
                    { "$match": { "active": true, "emitted_nullifier": Bson::Null } },
                    { "$project": { "_id": 0, "sender": 1 } }
                ]
            }
        },
        // 3. Look up all active (and non-nullified) 2nd degree relationships
        doc! {
            "$lookup": {
                "from": "relationships",
                "let": { "senderIds": "$first_degree_connections.sender", "original": "$_id" },
                "as": "second_degree_connections",
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {
                                "$and": [
                                    // Recipient is in 1st degree connections
                                    { "$in": ["$recipient", "$$senderIds"] },
                                    // Do not include 1st degree connections in 2nd degree connections
                                    { "$not": { "$in": ["$recipient", "$$senderIds"] } },
                                    // Do not include the actual user making the query
                                    { "$ne": ["$recipient", "$$original"] },
                                    // Ensure active (non-nullified)
                                    { "$eq": ["$active", true] },
                                    { "$eq": ["$emitted_nullifier", Bson::Null] }
                                ]
                            }
                        }
                    },
                    { "$project": { "_id": 1 } }
                ]
            }
        },
        // 4. Project out a count of the first and second degree connections
        doc! {
            "$project": {
                "_id": 0,
                "first_degrees": { "$size": "$first_degree_connections" },
                "second_degrees": { "$size": "$second_degree_connections" }
            }
        },
    ]
}

/**
 * Query for getting all the info needed to validate a degree proof
 *
 * @param username: The username of the user who is proving the degree
 * @param proof: The ObjectId of the previous proof the current degree doc is built upon
 * @returns the aggregation pipeline needed to retrieve the data from mongo
 */
pub fn degree_data(username: &String, proof: &ObjectId) -> Vec<Document> {
    vec![
        // 1. Look up the address of the proving user
        doc! { "$match": { "username": username } },
        doc! { "$project": { "address": 1, "_id": 1 } },
        // 2. Look up the matching proof document
        doc! { "$lookup": {
            "from": "proofs",
            "pipeline": [
                doc! { "$match": { "$expr": { "$eq": ["$_id", proof] } } },
                doc! { "$project": { "scope": 1, "degree": 1, "nullifiers": 1, "inactive": 1, "_id": 0 } }
            ],
            "as": "proofDoc"
        }},
        doc! { "$unwind": "$proofDoc" },
        // 3. Look up the scope address given in the proof document
        doc! { "$lookup": {
            "from": "users",
            "localField": "proofDoc.scope",
            "foreignField": "_id",
            "pipeline": [
                doc! { "$project": { "address": 1, "_id": 1 } }
            ],
            "as": "scopeAddress"
        }},
        doc! { "$unwind": "$scopeAddress" },
        // 4. Project out unnecessary data and reshape according to returned values
        doc! { "$project": {
            "_id": 0,
            "prover_oid": "$_id",
            "prover_address": "$address",
            "degree": "$proofDoc.degree",
            "nullifiers": "$proofDoc.nullifiers",
            "inactive": "$proofDoc.inactive",
            "scope": "$scopeAddress.address",
            "scope_oid": "$scopeAddress._id"
        }},
    ]
}

/**
 * Query for getting proven degrees for a user
 *
 * @param user: The username of the user to query the collection for degrees
 * @returns the aggregation pipeline needed to retrieve the data from mongo
 */
pub fn get_proven_degrees(user: &String) -> Vec<Document> {
    vec![
        // 1. Match the user
        doc! {"$match": { "username": user }},
        // 2. Find all proofs where the relation = user oid
        doc! {
            "$lookup": {
                "from": "proofs",
                "localField": "_id",
                "foreignField": "relation",
                "as": "proofs",
                "pipeline": [
                    doc! { "$match": { "inactive": { "$ne": true }, "degree": { "$gte": 1, "$lt": 8 } } },
                    doc! { "$project": { "degree": 1, "preceding": 1, "relation": 1, "scope": 1 } }
                ]
            }
        },
        doc! { "$unwind": "$proofs" },
        doc! {
            "$project": {
                "_id": "$proofs._id",
                "degree": "$proofs.degree",
                "scope": "$proofs.scope",
                "preceding": "$proofs.preceding",
            }
        },
        // 3. Lookup preceding relation
        doc! {
            "$lookup": {
                "from": "proofs",
                "localField": "preceding",
                "foreignField": "_id",
                "as": "precedingProof",
                "pipeline": [ doc! { "$project": { "_id": 0, "relation": 1 }} ]
            }
        },
        doc! {"$unwind": "$precedingProof"},
        // 3. Match scope username and preceding relation username
        doc! {
            "$lookup": {
                "from": "users",
                "localField": "scope",
                "foreignField": "_id",
                "as": "scopeUser",
                "pipeline": [ doc! { "$project": { "_id": 0, "username": 1 }} ]
            }
        },
        doc! {
            "$lookup": {
                "from": "users",
                "localField": "precedingProof.relation",
                "foreignField": "_id",
                "as": "precedingRelationUser",
                "pipeline": [ doc! { "$project": { "_id": 0, "username": 1 }} ]
            }
        },
        doc! {
            "$project": {
                "_id": "$_id",
                "degree": "$degree",
                "scope": { "$arrayElemAt": ["$scopeUser.username", 0] },
                "relation": { "$arrayElemAt": ["$precedingRelationUser.username", 0] },
            }
        },
    ]
}

/**
 * Query for getting a one-way relationship document between users given their usernames
 *
 * @param sender: The username of the sender (creator of the stored auth secret/ nullifier emitter)
 * @param recipient: The username of the recipient (user of the stored auth secret)
 * @param full: Whether to return the full relationship document or just the ObjectId
 * @returns the aggregation pipeline needed to retrieve the data from mongo
 */
pub fn get_relationship(sender: &String, recipient: &String, full: bool) -> Vec<Document> {
    // optional doc for projecting only the ObjectId of the document
    let mut lookup_pipeline = vec![doc! { "$match": { "$expr": { "$and": [
        { "$eq": ["$sender", "$$senderId"] },
        { "$eq": ["$recipient", "$$recipientId"] }
    ]}}}];
    if !full {
        lookup_pipeline.push(doc! { "$project": { "_id": 1 } });
    }
    // pipeline definition
    vec![
        // 1. Look up the ObjectIDs of the sender and recipient
        doc! {
            "$facet": {
                "sender": [
                    { "$match": { "username": sender } },
                    { "$project": { "sender": "$_id" } }
                ],
                "recipient": [
                    { "$match": { "username": recipient } },
                    { "$project": { "recipient": "$_id" } }
                ]
            }
        },
        doc! {
            "$project": {
                "sender": { "$arrayElemAt": ["$sender.sender", 0] },
                "recipient": { "$arrayElemAt": ["$recipient.recipient", 0] }
            }
        },
        // 2. Look up the relationship document with matching sender and recipient
        doc! {
            "$lookup": {
                "from": "relationships",
                "let": { "senderId": "$sender", "recipientId": "$recipient" },
                "pipeline": lookup_pipeline,
                "as": "relationship"
            }
        },
        doc! { "$unwind": "$relationship" },
        // 3. Return only the retrieved relationship document (or only the OID)
        doc! { "$replaceRoot": { "newRoot": "$relationship" }},
    ]
}

/**
 * Query for getting a one-way relationship document between users given their usernames
 *
 * @param from: The username of the sender (creator of the stored auth secret/ nullifier emitter)
 * @param to: The username of the recipient (user of the stored auth secret)
 * @returns the aggregation pipeline needed to retrieve the data from mongo
 */
pub fn reject_relationship(from: &String, to: &String) -> Vec<Document> {
    vec![
        // get the ObjectID of the recipient of the relationship request
        doc! { "$match": { "username": to } },
        doc! { "$project": { "_id": 1 } },
        // lookup the ObjectID of the sender of the relationship request
        doc! {
            "$lookup": {
                "from": "users",
                "let": { "from": from },
                "as": "sender",
                "pipeline": [
                    doc! { "$match": { "$expr": { "$eq": ["$username", "$$from"] } } },
                    doc! { "$project": { "_id": 1 } }
                ],
            }
        },
        doc! { "$unwind": "$sender" },
        // project the ObjectID's of the sender and recipient
        doc! { "$project": { "recipient": "$_id", "sender": "$sender._id" } },
        // lookup the ObjectID of the pending relationship to delete
        doc! {
            "$lookup": {
                "from": "relationships",
                "let": { "sender": "$sender", "recipient": "$recipient" },
                "as": "relationship",
                "pipeline": [
                    doc! {
                        "$match": {
                            "$expr": {
                                "$and": [
                                    { "$eq": ["$sender", "$$sender"] },
                                    { "$eq": ["$recipient", "$$recipient"] },
                                    { "$eq": ["$active", false ] }
                                ]
                            }
                        }
                    },
                    doc! { "$project": { "_id": 1 } }
                ],
            }
        },
        doc! { "$unwind": "$relationship" },
        // project the ObjectID of the pending relationship to delete
        doc! { "$project": { "relationship": "$relationship._id", "_id": 0 } },
    ]
}

/**
 * Query for getting the usernames of all relationships (active or pending) for a given user
 *
 * @param user: The username of the user to get relationships for
 * @param active: If true, get active relationships, else get pending relationships the user can accept
 * @returns the aggregation pipeline needed to retrieve the data from mongo
 */
pub fn get_relationships_usernames(user: &String, active: bool) -> Vec<Document> {
    vec![
        // 1. get the ObjectID of the user doc for the given username
        doc! { "$match": { "username": user } },
        doc! { "$project": { "_id": 1 } },
        // 2. Lookup all (pending/ active) relationships for the user
        doc! {
            "$lookup": {
                "from": "relationships",
                "localField": "_id",
                "foreignField": "recipient",
                "as": "relationships",
                "pipeline": [
                    doc! { "$match": { "$expr": { "$eq": ["$active", active] } } },
                    doc! { "$project": { "sender": 1, "_id": 0 } },
                ],
            }
        },
        doc! { "$unwind": "$relationships" },
        // 3. Look up counterparty relationship to check if user has nullified (only active)
        // doc! {
        //     "$lookup": {
        //         "from": "relationships",
        //         "localField": "_id",
        //         "foreignField": "sender",
        //         "as": "sentRelationships",
        //         "pipeline": [
        //             doc! { "$match": { "$expr": {
        //                 "$eq": ["$recipient", "$relationships.sender"]
        //             } } },
        //             doc! { "$project": { "emitted_nullifier": 1, "_id": 0 } },
        //         ],
        //     }
        // },
        // doc! { "$unwind": "$sentRelationships" },
        // 4. Look up the usernames of found relationship senderss
        doc! {
            "$lookup": {
                "from": "users",
                "localField": "relationships.sender",
                "foreignField": "_id",
                "as": "relationships",
                "pipeline": [ doc! { "$project": { "username": 1, "_id": 0 } }],
            }
        },
        doc! { "$unwind": "$relationships" },
        // 5. Project only the usernames of the relationships
        doc! { "$project": { "username": "$relationships.username", "_id": 0 } },
    ]
}

/**
 * Query for getting the `AvailableDegrees` data for available proofs to build for a user
 *
 * @param user: The username of the user to get available degrees for
 * @returns the aggregation pipeline needed to retrieve the data from mongo
 */
pub fn available_degrees(user: &String) -> Vec<Document> {
    vec![
        // 1. Match the user
        doc! {"$match": { "username": user }},
        // 2. Lookup relationships where the user is the recipient
        // todo: prevent use of inactive + nullified relationships
        doc! {
            "$lookup": {
                "from": "relationships",
                "let": { "userId": "$_id" },
                "pipeline": [
                    doc! { "$match": { "$expr": { "$eq": ["$recipient", "$$userId"] }}},
                    doc! { "$project": { "sender": 1, "_id": 0 } }
                ],
                "as": "userRelationships"
            }
        },
        doc! { "$unwind": "$userRelationships" },
        doc! {
            "$project": {
                "user": "$_id",
                "sender": "$userRelationships.sender",
                "_id": 0
            }
        },
        // 3. Find all proofs where the relation = any of the senders from relationships
        doc! {
            "$lookup": {
                "from": "proofs",
                "localField": "sender",
                "foreignField": "relation",
                "as": "proofs",
                "pipeline": [
                    doc! { "$match": { "inactive": { "$ne": true }, "degree": { "$lt": 8 } } },
                    doc! { "$project": { "degree": 1, "scope": 1 } }
                ]
            }
        },
        doc! { "$unwind": "$proofs" },
        doc! {
            "$project": {
                "_id": "$proofs._id",
                "user": 1,
                "degree": "$proofs.degree",
                "scope": "$proofs.scope",
                "relation": "$sender"
            }
        },
        // 4. Sort by scope, then order by lowest degree
        doc! { "$sort": { "scope": 1, "degree": 1 }},
        // 5. group by the scope and return the lowest degree value
        doc! {
            "$group": {
                "_id": "$scope",
                "originalId": { "$first": "$_id" },
                "degree": { "$first": "$degree" },
                "relation": { "$first": "$relation" },
                "user": { "$first": "$user"}
            }
        },
        doc! {
            "$project": {
                "_id": "$originalId",
                "degree": 1,
                "scope": "$_id",
                "relation": 1,
                "user": 1
            }
        },
        // 6. Find matching proofs for the same scope made by the user
        doc! {
            "$lookup": {
                "from": "proofs",
                "let": {
                    "scopeId": "$scope",
                    "relationId": "$user",
                    "currentDegree": "$degree"
                },
                "pipeline": [
                    doc! {
                        "$match": {
                            "$expr": {
                                "$and": [
                                    { "$eq": ["$scope", "$$scopeId"] },
                                    { "$eq": ["$relation", "$$relationId"] },
                                    { "$lt": ["$degree", { "$add": ["$$currentDegree", 2] }] }
                                ]
                            }
                        }
                    },
                    doc! { "$project": { "_id": 1, "degree": 1, "scope": 1, "relation": 1 } }
                ],
                "as": "existingProofs"
            }
        },
        // 7. Filter out proofs that would not allow user to build a lower degree proof than they currently have
        doc! { "$match": { "existingProofs": { "$eq": [] }}},
        // 8. Match scope and relation usernames
        doc! {
            "$lookup": {
                "from": "users",
                "localField": "scope",
                "foreignField": "_id",
                "as": "scopeUser",
                "pipeline": [ doc! { "$project": { "_id": 0, "username": 1 }} ]
            }
        },
        doc! {
            "$lookup": {
                "from": "users",
                "localField": "relation",
                "foreignField": "_id",
                "as": "relationUser",
                "pipeline": [ doc! { "$project": { "_id": 0, "username": 1 }} ]
            }
        },
        // 9. Reshape final document for AvailableProofs struct
        doc! {
            "$project": {
                "_id": 1,
                "degree": 1,
                "scope": { "$arrayElemAt": ["$scopeUser.username", 0] },
                "relation": { "$arrayElemAt": ["$relationUser.username", 0] }
            }
        },
    ]
}

/**
 * Query for getting a proof document given the username of the prover and the identity scope of the proof chain
 *
 * @param username: The username of the prover
 * @param scope: The username of the identity scope of the proof chain
 * @returns the aggregation pipeline needed to retrieve the data from mongo
 */
pub fn proof_by_scope(username: &String, scope: &String) -> Vec<Document> {
    vec![
        // 1. Find the ObjectIDs of the user and scope
        doc! {
            "$facet": {
                "relation": [
                    { "$match": { "username": username } },
                    { "$project": { "_id": 1 } }
                ],
                "scope": [
                    { "$match": { "username": scope } },
                    { "$project": { "_id": 1 } }
                ]
            }
        },
        doc! {
            "$project": {
                "relation": { "$arrayElemAt": ["$relation._id", 0] },
                "scope": { "$arrayElemAt": ["$scope._id", 0] }
            }
        },
        // 2. Look up the proof document with the matching relation and scope
        doc! {
            "$lookup": {
                "from": "proofs",
                "let": { "relationId": "$relation", "scopeId": "$scope" },
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {
                                "$and": [
                                    { "$eq": ["$relation", "$$relationId"] },
                                    { "$eq": ["$scope", "$$scopeId"] }
                                ]
                            }
                        }
                    }
                ],
                "as": "proof"
            }
        },
        doc! { "$unwind": "$proof" },
        // 3. Return only the proof document
        doc! { "$replaceRoot": { "newRoot": "$proof" }},
    ]
}

/**
 * Query for getting proof metadata for a particular prover and scope
 *
 * @param username: The username of the prover
 * @param scope: The username of the identity scope of the proof chain
 * @returns the aggregation pipeline needed to retrieve the data from mongo
 */
// TODO: Need to handle indentity proof
pub fn proof_metadata_by_scope(username: &String, scope: &String) -> Vec<Document> {
    vec![
        // 1. Find the ObjectIDs of the user and scope
        doc! {
            "$facet": {
                "relation": [
                    { "$match": { "username": username } },
                    { "$project": { "_id": 1 } }
                ],
                "scope": [
                    { "$match": { "username": scope } },
                    { "$project": { "_id": 1 } }
                ]
            }
        },
        doc! {
            "$project": {
                "relation": { "$arrayElemAt": ["$relation._id", 0] },
                "scope": { "$arrayElemAt": ["$scope._id", 0] }
            }
        },
        // 2. Look up the proof document with the matching relation and scope
        doc! {
            "$lookup": {
                "from": "proofs",
                "let": { "relationId": "$relation", "scopeId": "$scope" },
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {
                                "$and": [
                                    { "$eq": ["$relation", "$$relationId"] },
                                    { "$eq": ["$scope", "$$scopeId"] }
                                ]
                            }
                        }
                    },
                    {
                        "$project": {
                            "_id": 1,
                            "degree": 1,
                            "scope": 1,
                            "preceding": 1
                        }
                    }
                ],
                "as": "proof"
            }
        },
        doc! { "$unwind": "$proof" },
        // 3. Return only the proof document
        doc! { "$replaceRoot": { "newRoot": "$proof" }},
        // 4. Lookup preceding proof and get relation from it
        doc! {
            "$lookup": {
                "from": "proofs",
                "localField": "preceding",
                "foreignField": "_id",
                "as": "precedingProof",
                "pipeline": [ doc! { "$project": { "_id": 0, "relation": 1 }} ]
            }
        },
        doc! {"$unwind": "$precedingProof"},
        // 5. Lookup preceding relation username
        doc! {
            "$lookup": {
                "from": "users",
                "localField": "precedingProof.relation",
                "foreignField": "_id",
                "as": "precedingRelationUser",
                "pipeline": [ doc! { "$project": { "_id": 0, "username": 1 }} ]
            }
        },
        doc! {
            "$project": {
                "_id": 1,
                "degree": 1,
                "scope": scope,
                "relation": { "$arrayElemAt": ["$precedingRelationUser.username", 0] },
            }
        },
    ]
}

pub fn proving_data(user: &String, proof: &ObjectId) -> Vec<Document> {
    vec![
        // 1. Find the matching proof
        doc! { "$match": { "_id": proof }},
        // 2. Look up the pubkey of the proof creator
        doc! {
            "$lookup": {
                "from": "users",
                "localField": "relation",
                "foreignField": "_id",
                "as": "relation_pubkey",
                "pipeline": [{ "$project": { "_id": 0, "pubkey": 1 }}]
            }
        },
        doc! { "$unwind": "$relation_pubkey" },
        doc! { "$set": { "relation_pubkey": "$relation_pubkey.pubkey" }},
        // 3. Look up the OID of the user requesting proof data given the username
        doc! {
            "$lookup": {
                "from": "users",
                "let": { "username": user },
                "pipeline": [
                    {"$match": { "$expr": { "$eq": [ "$username", "$$username" ] }}},
                    { "$project": { "_id": 1 }}
                ],
                "as": "user_id"
            }
        },
        doc! { "$unwind": "$user_id" },
        doc! { "$set": { "user_id": "$user_id._id" }},
        // 4. Look up the nullifier and auth signature for the given relationship
        doc! {
            "$lookup": {
                "from": "relationships",
                "let": { "sender": "$relation", "recipient": "$user_id" },
                "pipeline": [
                    {
                        "$match": {
                            "$expr": {
                                "$and": [
                                    { "$eq": [ "$sender", "$$sender" ] },
                                    { "$eq": [ "$recipient", "$$recipient" ] }
                                ]
                            }
                        }
                    },
                    {
                        "$project": {
                            "_id": 0,
                            "nullifier_ciphertext": 1,
                            "signature_ciphertext": 1,
                            "ephemeral_key": 1
                        }
                    }
                ],
                "as": "relationship"
            }
        },
        doc! { "$unwind": "$relationship" },
        // 5: Project only necessary fields
        doc! {
            "$project": {
                "_id": 0,
                "proof": 1,
                "relation_pubkey": 1,
                "nullifier_ciphertext": "$relationship.nullifier_ciphertext",
                "signature_ciphertext": "$relationship.signature_ciphertext",
                "ephemeral_key": "$relationship.ephemeral_key"
            }
        },
    ]
}

pub fn nullifiers_emitted(nullifiers: &Vec<[u8; 32]>) -> Vec<Document> {
    // prune the nullifiers that are 0x00
    let nullifiers: Vec<[u8; 32]> = nullifiers
        .iter()
        .filter(|nullifier| **nullifier != [0; 32])
        .map(|nullifier| *nullifier)
        .collect();
    // define the conditoinal matching
    let match_conditions: Vec<_> = nullifiers
        .iter()
        .map(|nullifier| doc! { "emitted_nullifier": { "$eq": nullifier.to_vec().to_bson() }})
        .collect();
    // pipeline to count relationships that match any of the emitted nullifiers
    vec![
        doc! { "$match": { "$or": match_conditions }},
        doc! { "$count": "matchedCount" },
    ]
}

/**
 * Query for getting all removable degree proofs when upserting a new degree proof
 * @notice assumes scope and relation OID's have been obtained in previous query
 * @todo: only return "removable" oids if they are actually removable
 *
 * @param scope: The ObjectId of the scope of the degree proof chain
 * @param relation: The ObjectId of the prover submitting a new degree proof
 *
 * @returns the aggregation pipeline needed to retrieve the data from mongo
 */
pub fn degree_proof_dependencies(scope: &ObjectId, relation: &ObjectId) -> Vec<Document> {
    vec![
        // 1. Try to find an active degree proof for the prover on the given identity scope
        doc! { "$match": { "relation": relation, "scope": scope, "inactive": false }},
        // Project to exclude proof and nullifiers
        doc! { "$project": { "proof": 0, "nullifiers": 0 }},
        // 2. Look at lower degrees to see if they are marked inactive
        doc! {
            "$graphLookup": {
                "from": "proofs",
                "startWith": "$_id",
                "connectFromField": "preceding",
                "connectToField": "_id",
                "as": "upstream_chain",
                "depthField": "level",
                "restrictSearchWithMatch": {
                    "$expr": {
                        "$or": [
                            { "$eq": ["$inactive", true] },
                            {
                                "$and": [
                                    { "$eq": ["$_id", "$$ROOT._id"] },
                                    { "$eq": ["$relation", relation] },
                                    { "$eq": ["$scope", scope] }
                                ]
                            }
                        ]
                    }
                }
            }
        },
        doc! { "$unwind": { "path": "$upstream_chain" }},
        // 3. Project the necessary info for sorting and grouping by level
        doc! {
            "$project": {
                "_id": "$upstream_chain._id",
                "degree": "$upstream_chain.degree"
            }
        },
        // 4. Look up all downstream proofs from each level
        doc! {
            "$graphLookup": {
                "from": "proofs",
                "startWith": "$_id",
                "connectFromField": "_id",
                "connectToField": "preceding",
                "as": "downstream_chain",
                "depthField": "level"
            }
        },
        doc! { "$unwind": { "path": "$downstream_chain", "preserveNullAndEmptyArrays": true }},
        // 5. Project the necessary info for sorting and grouping by level
        doc! {
            "$project": {
                "grouping": "$_id",
                "grouping_degree": "$degree",
                "_id": "$downstream_chain._id",
                "degree": "$downstream_chain.degree",
                "inactive": "$downstream_chain.inactive"
            }
        },
        // 6. Group so that the highest degree level for removal claims unique documents under it
        doc! {
            "$group": {
                "_id": "$_id",
                "docs": { "$push": "$$ROOT" },
                "maxGroupingDegree": { "$max": "$grouping_degree" }
            }
        },
        // Group by `grouping` and keep only the highest `grouping_degree` for each `_id`
        doc! {
            "$group": {
                "_id": "$docs.grouping",
                "grouping_degree": { "$max": "$maxGroupingDegree" },
                "docs": { "$push": "$docs" }
            }
        },
        doc! { "$unwind": "$docs" },
        doc! { "$unwind": "$docs" },
        // Match documents with the highest `grouping_degree`
        doc! {
            "$match": {
                "$expr": { "$eq": ["$docs.grouping_degree", "$grouping_degree"] }
            }
        },
        // Project the desired fields
        doc! {
            "$project": {
                "grouping": "$docs.grouping",
                "grouping_degree": "$docs.grouping_degree",
                "_id": "$docs._id",
                "degree": "$docs.degree",
                "inactive": "$docs.inactive"
            }
        },
        // Sort by `grouping_degree` and `degree`
        doc! { "$sort": { "grouping_degree": 1, "degree": 1 }},
        // 7. Group by `grouping`, keeping all `_id` in `groupings`, and collect downstream proofs
        doc! {
            "$group": {
                "_id": "$grouping",
                "groupings": { "$addToSet": "$_id" },
                "grouping_degree": { "$first": "$grouping_degree" },
                "downstream": {
                    "$push": {
                        "proofId": "$_id",
                        "inactive": "$inactive",
                        "degree": "$degree"
                    }
                }
            }
        },
        // 8. Group all documents and collect all groupings
        doc! {
            "$group": {
                "_id": null,
                "allGroupings": { "$addToSet": "$_id" },
                "docs": { "$push": "$$ROOT" }
            }
        },
        doc! { "$unwind": "$docs" },
        // Replace the root with the merged document
        doc! {
            "$replaceRoot": {
                "newRoot": {
                    "$mergeObjects": ["$docs", { "allGroupings": "$allGroupings" }]
                }
            }
        },
        // Project the final structure with filtered downstream proofs
        doc! {
            "$project": {
                "_id": 1,
                "degree": "$grouping_degree",
                "downstream": {
                    "$filter": {
                        "input": "$downstream",
                        "as": "item",
                        "cond": { "$not": { "$in": ["$$item.proofId", "$allGroupings"] }}
                    }
                }
            }
        },
        // 9. Fix downstream array if it contains an empty object
        doc! {
            "$addFields": {
                "downstream": {
                    "$cond": {
                        "if": {
                            "$and": [
                                { "$isArray": "$downstream" },
                                { "$eq": [{ "$size": "$downstream" }, 1] },
                                { "$eq": [{ "$arrayElemAt": ["$downstream", 0] }, {}] }
                            ]
                        },
                        "then": Bson::Array(vec![]),
                        "else": "$downstream"
                    }
                }
            }
        },
        // 10. Reshape downstream proofs to include only proofId and determine if removable
        doc! {
            "$addFields": {
                "downstream": {
                    "$map": {
                        "input": "$downstream",
                        "as": "item",
                        "in": "$$item.proofId"
                    }
                },
                "removable": {
                    "$eq": [
                        { "$size": { "$filter": {
                            "input": "$downstream",
                            "as": "item",
                            "cond": { "$eq": ["$$item.inactive", true] }
                        }}},
                        { "$size": "$downstream" }
                    ]
                }
            }
        },
        // 11. Sort by degree in descending order
        doc! { "$sort": { "degree": -1 }},
    ]
}

/**
 * Query for getting a list of nullified relationships
 *
 * @param user: The username of the prover
 * @returns the aggregation pipeline needed to retrieve the data from mongo
 */
pub fn nullified_relationships(user: &String) -> Vec<Document> {
    vec![
        // 1. Match the user
        doc! {"$match": { "username": user}},
        // 2. Lookup relationships where the user is the sender and has not emitted a nullifier
        doc! {
            "$lookup": {
                "from": "relationships",
                "let": { "userId": "$_id" },
                "pipeline": [
                    doc! { "$match": { "$expr": {
                        "$and": [
                            { "$eq": ["$sender", "$$userId"] },
                            { "$eq": ["$emitted_nullifier", null] }
                        ]
                    }}},
                    doc! { "$project": { "recipient": 1, "_id": 0 } }
                ],
                "as": "senderRelationships"
            }
        },
        doc! { "$unwind": "$senderRelationships" },
        doc! {
            "$project": {
                "user": "$_id",
                "recipient": "$senderRelationships.recipient",
                "_id": 0
            }
        },
        // 3. Check whether nullifier has been emitted in relationship where user is recipient
        doc! {
            "$lookup": {
                "from": "relationships",
                "let": { "senderId": "$recipient", "recipientId": "$user" },
                "pipeline": [
                    doc! { "$match": { "$expr": {
                        "$and": [
                            { "$eq": ["$sender", "$$senderId"] },
                            { "$eq": ["$recipient", "$$recipientId"] },
                            { "$ne": ["$emitted_nullifier", null] }
                        ]
                    }}},
                    doc! { "$project": { "sender": 1, "_id": 0 } }
                ],
                "as": "recipientRelationships"
            }
        },
        doc! { "$unwind": "$recipientRelationships" },
        doc! {
            "$project": {
                "user": "$recipientRelationships.sender",
            }
        },
        // 4. Look up username of user
        doc! {
            "$lookup": {
                "from": "users",
                "localField": "user",
                "foreignField": "_id",
                "as": "userDetails"
              }
        },
        doc! { "$unwind": "$userDetails" },
        doc! {
           "$project": {
               "username": "$userDetails.username"
           }
        },
    ]
}
