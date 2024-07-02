use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateUserRequest {
    pub username: String, // the username of the user to create
    pub pubkey: [u8; 32], // the pubkey of the user to create
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>, // compressed identity proof
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PhraseRequest {
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>, // compressed proof
    #[serde(with = "serde_bytes")]
    pub ciphertext: [u8; 192], // encrypted phrase
    pub description: String, // description (discarded if phrase already exists)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetNonceRequest {
    pub username: String,
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TestProofCompressionRequest {
    pub proof: Vec<u8>,
    pub username: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewRelationshipRequest {
    #[serde(with = "serde_bytes")]
    pub nullifier_secret: [u8; 48],
    pub to: String,
    #[serde(with = "serde_bytes")]
    pub ephemeral_key: [u8; 32],
    // TODO: Rename to encrypted auth secret
    #[serde(with = "serde_bytes")]
    pub ciphertext: [u8; 80],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DegreeProofRequest {
    pub proof: Vec<u8>,
    pub previous: String,
    pub degree: u8,
}
