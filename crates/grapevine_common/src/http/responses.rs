use bson::oid::ObjectId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProofMetadata {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub degree: u8,
    pub scope: String,
    pub relation: String,
}
