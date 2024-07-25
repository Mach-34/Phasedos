use crate::utils::ToBson;
use mongodb::bson::{doc, oid::ObjectId, Document};
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
        // 3. Look up the usernames of found relationship senderss
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
        // 4. Project only the usernames of the relationships
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
        doc! { "$match": { "username": user } },
        // 2. Lookup relationships where the user is the recipient
        doc! {
            "$lookup": {
                "from": "relationships",
                "let": { "userId": "$_id" },
                "pipeline": [
                    doc! {
                        "$match": {
                            "$expr": { "$eq": ["$recipient", "$$userId"] }
                        }
                    },
                    doc! { "$project": { "sender": 1, "_id": 0 } }
                ],
                "as": "userRelationships"
            }
        },
        doc! { "$unwind": "$userRelationships" },
        doc! {
            "$project": {
                "sender": "$userRelationships.sender",
                "_id": 0
            }
        },
        // 3. Find all proofs where the relation = any of the senders from relationships
        // todo: filter out inactive proofs and proofs > 8
        doc! {
            "$lookup": {
                "from": "proofs",
                "localField": "sender",
                "foreignField": "relation",
                "as": "proofs",
                "pipeline": [
                    doc! { "$match": { "inactive": { "$ne": true } } },
                    doc! { "$project": { "degree": 1, "scope": 1 } }
                ]
            }
        },
        doc! { "$unwind": "$proofs" },
        // 4. Intermediate reshape of the document
        doc! {
            "$project": {
                "_id": "$proofs._id",
                "degree": "$proofs.degree",
                "scope": "$proofs.scope",
                "relation": "$sender"
            }
        },
        // 5. Lookup the username for the proof chain's identity scope
        doc! {
            "$lookup": {
                "from": "users",
                "localField": "scope",
                "foreignField": "_id",
                "as": "scopeUser",
                "pipeline": [
                    doc! { "$project": { "_id": 0, "username": 1 } }
                ]
            }
        },
        // 6. Lookup the username for the relation given in the available proof to build from
        doc! {
            "$lookup": {
                "from": "users",
                "localField": "relation",
                "foreignField": "_id",
                "as": "relationUser",
                "pipeline": [
                    doc! { "$project": { "_id": 0, "username": 1 } }
                ]
            }
        },
        // 7. Final projection to format the output
        doc! {
            "$project": {
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

// pub fn degree_proof_dependencies() -> Vec<Document> {
//     vec![
//         doc! {
//           "$match": {
//             "user": user,
//             "phrase": proof.phrase
//           }
//         },
//         doc! {
//           "$graphLookup": {
//             "from": "degree_proofs",
//             "startWith": "$preceding", // Assuming 'preceding' is a field that points to the parent document
//             "connectFromField": "preceding",
//             "connectToField": "_id",
//             "as": "preceding_chain",
//           }
//         },
//         doc! {
//             "$project": {
//                 "_id": 1,
//                 "degree": 1,
//                 "inactive": 1,
//                 "preceding": 1,
//                 "proceeding": 1,
//                 "preceding_chain": {
//                     "$map": {
//                         "input": "$preceding_chain",
//                         "as": "chain",
//                         "in": {
//                             "_id": "$$chain._id",
//                             "degree": "$$chain.degree",
//                             "inactive": "$$chain.inactive",
//                             "preceding": "$$chain.preceding",
//                             "proceeding": "$$chain.proceeding",
//                         }
//                     }
//                 }
//             }
//         },
//     ]
// }
