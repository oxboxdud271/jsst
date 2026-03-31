use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use aes_gcm::aead::consts::U32;
use aes_gcm::aead::generic_array::GenericArray;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde_json::json;
use crate::vault::VaultClient;

pub type GenericErr<T = (), E = Box<dyn Error>> = Result<T, E>;
type AES256Key = GenericArray<u8, U32>;

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


impl VaultDataKey {
    pub fn retrieve_data_key(
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

    pub fn to_aes_256_key(&self) -> GenericErr<AES256Key> {
        let decoded = BASE64_STANDARD.decode(self.plaintext.as_bytes())?;
        match decoded.as_array::<32>() {
            Some(data) => {
                let key = AES256Key::from_slice(data);
                Ok(*key)
            },
            None => Err("Invalid Data Key".into())
        }
    }
}