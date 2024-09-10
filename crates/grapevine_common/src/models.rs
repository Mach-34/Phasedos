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

// todo: maybe move this somewhere else? is not used in transport
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DegreeProofValidationData {
    #[serde(default, with = "serde_bytes")]
    pub prover_address: [u8; 32],
    pub prover_oid: ObjectId,
    #[serde(default, with = "serde_bytes")]
    pub scope: [u8; 32],
    pub scope_oid: ObjectId,
    pub nullifiers: Vec<[u8; 32]>,
    pub degree: u8,
    pub inactive: bool,
}

// all data needed from server to prove a degree of separation
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProvingData {
    #[serde(default, with = "serde_bytes")]
    pub relation_pubkey: [u8; 32],
    #[serde(default, with = "serde_bytes")]
    pub proof: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub ephemeral_key: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub signature_ciphertext: [u8; 80],
    #[serde(with = "serde_bytes")]
    pub nullifier_ciphertext: [u8; 48],
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Relationship {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub active: Option<bool>, // true if both users have accepted, false if pending
    pub sender: Option<ObjectId>,
    pub recipient: Option<ObjectId>,
    #[serde(default, with = "serde_bytes")]
    pub ephemeral_key: Option<[u8; 32]>, // pubkey + recipient privkey decrypts auth secret
    #[serde(default, with = "serde_bytes")]
    pub emitted_nullifier: Option<[u8; 32]>, // if Some, then relationship is nullified
    #[serde(default, with = "serde_bytes")]
    pub signature_ciphertext: Option<[u8; 80]>, // decryptable by recipient for proving
    #[serde(default, with = "serde_bytes")]
    pub nullifier_ciphertext: Option<[u8; 48]>, // decryptable by recipient for proving
    #[serde(default, with = "serde_bytes")]
    pub nullifier_secret_ciphertext: Option<[u8; 48]>, // decryptable by sender for nullifier emission
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
    pub address: Option<[u8; 32]>, // the hashed pubkey of the user
}
