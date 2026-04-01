use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::consts::U32;
use serde_json::json;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use crate::util;
use crate::util::GenericErr;
use crate::vault::VaultClient;

type AES256Key = GenericArray<u8, U32>;

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
            plaintext: util::json_to_string(&data_key["data"]["plaintext"]),
            ciphertext: util::json_to_string(&data_key["data"]["ciphertext"])
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

    pub fn from_cipher(client: &VaultClient, cipher: &str, key: &str) -> GenericErr<Self> {
        let resp = client.post(
            &String::from(format!("/v1/transit/decrypt/{}", key)),
            &json!({
                "ciphertext": cipher
            })
        )?;
        Ok(Self {
            ciphertext: String::from(cipher),
            plaintext: util::json_to_string(&resp["data"]["plaintext"])
        })
    }
}