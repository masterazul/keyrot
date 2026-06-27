use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Sealed {
    pub nonce: String,
    pub ct: String,
}

#[derive(Serialize, Deserialize)]
pub struct Kdf {
    pub algo: String,
    pub salt: String,
}

#[derive(Serialize, Deserialize)]
pub struct Version {
    pub version: u32,
    pub created_at: u64,
    pub nonce: String,
    pub ct: String,
}

#[derive(Serialize, Deserialize)]
pub struct Secret {
    pub current: u32,
    pub versions: Vec<Version>,
}

#[derive(Serialize, Deserialize)]
pub struct Vault {
    pub format: u32,
    pub kdf: Kdf,
    pub dek: Sealed,
    pub secrets: BTreeMap<String, Secret>,
}
