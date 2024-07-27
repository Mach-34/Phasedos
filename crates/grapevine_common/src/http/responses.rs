use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DegreeData {
    pub degree: Option<u8>,
    pub scope: Option<String>,
    pub relation: Option<String>,
}
