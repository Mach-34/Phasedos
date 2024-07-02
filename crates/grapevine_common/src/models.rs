use bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GrapevineProof {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub degree: Option<u8>, // the degree of separation from scope to relation
    pub scope: Option<ObjectId>, // the id of the identity proof creator
    pub relation: Option<ObjectId>, // the prover demonstrating degree of separation from scope
    pub nullifiers: Option<Vec<[u8; 32]>>, // nullififiers used in this proof
    #[serde(default, with = "serde_bytes")]
    pub proof: Option<Vec<u8>>, // compressed proof
    pub preceding: Option<ObjectId>, // the proof that this proof is built on (null if first)
    pub inactive: Option<bool>,
}

// // all data needed from server to prove a degree of separation
// #[derive(Debug, Serialize, Deserialize, Clone)]
// pub struct ProvingData {
//     pub phrase_index: u32,
//     #[serde(default, with = "serde_bytes")]
//     pub phrase_hash: [u8; 32],
//     pub description: String,
//     pub degree: u8, // multiply by 2 to get iterations
//     pub proof: Vec<u8>,
//     pub username: String,
//     #[serde(with = "serde_bytes")]
//     pub ephemeral_key: [u8; 32],
//     #[serde(with = "serde_bytes")]
//     pub ciphertext: [u8; 80],
// }

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Relationship {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub recipient: Option<ObjectId>, // use this privkey to decrypt
    pub sender: Option<ObjectId>,
    #[serde(default, with = "serde_bytes")]
    pub nullifier_secret: Option<[u8; 48]>,
    #[serde(default, with = "serde_bytes")]
    pub ephemeral_key: Option<[u8; 32]>,
    #[serde(default, with = "serde_bytes")]
    pub ciphertext: Option<[u8; 80]>,
    pub active: Option<bool>, // true if both users have accepted, false if pending
}

// All fields optional to allow projections
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub nonce: Option<u64>,
    pub username: Option<String>,
    #[serde(with = "serde_bytes")]
    pub pubkey: Option<[u8; 32]>, // the pubkey of the user
    #[serde(with = "serde_bytes")]
    pub address: Option<[u8; 32]> // the hashed pubkey of the user
}