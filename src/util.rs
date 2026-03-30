use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json::json;
use crate::vault::VaultClient;

pub type GenericErr<T = (), E = Box<dyn Error>> = Result<T, E>;


pub fn get_epoch() -> u64 {
    let now = SystemTime::now();
    match now.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_secs(),
        Err(_) => 0,
    }
}

pub fn json_to_string(json: &serde_json::Value) -> String {
    String::from(json.as_str().unwrap())
}


pub struct VaultDataKey {
    pub ciphertext: String,
    pub plaintext: String,
}


pub fn retrieve_data_key_from_vault(
    client: &VaultClient,
    key_name: &str,
    key_size: &u32
) -> GenericErr<VaultDataKey> {
    let data_key = client.post(
        &String::from(format!("/v1/transit/datakey/plaintext/{}", key_name)),
        &json!({
                "bits": key_size
            })
    )?;
    Ok(VaultDataKey {
        plaintext: json_to_string(&data_key["data"]["plaintext"]),
        ciphertext: json_to_string(&data_key["data"]["ciphertext"])
    })
}