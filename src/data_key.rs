use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::consts::{U12, U32};
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::Aead;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde_json::json;
use crate::util;
use crate::util::GenericErr;
use crate::vault::VaultClient;

type AES256Key = GenericArray<u8, U32>;
pub type NonceVal = GenericArray<u8, U12>;

pub struct VaultDataKey {
    pub ciphertext: String,
    pub plaintext: String,
}

pub struct RawVaultCipher {
    pub iv: [u8; 12],
    pub data: Vec<u8>,
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

    pub fn vec_to_key(data: &Vec<u8>) -> GenericErr<AES256Key> {
        match data.as_array::<32>() {
            Some(data) => {
                let key = AES256Key::from_slice(data);
                Ok(*key)
            },
            None => Err("Invalid Data Key".into())
        }
    }

    pub fn decode_raw_cipher(ciphertext: &str) -> GenericErr<RawVaultCipher> {
        let key_parts: Vec<&str> = ciphertext.split(":").collect();
        if key_parts.len() != 3 {
            return Err("Invalid Cipher".into())
        }
        let cipher = BASE64_STANDARD.decode(key_parts[2].trim())?;
        let mut iv: [u8; 12] = [0; 12];
        iv.clone_from_slice(&cipher[0..12]);

        let mut data: Vec<u8> = vec![0; cipher.len() - 12];
        data.clone_from_slice(&cipher[12..]);

        Ok(RawVaultCipher { iv, data })
    }

    pub fn to_aes_256_key(&self) -> GenericErr<AES256Key> {
        let decoded = BASE64_STANDARD.decode(self.plaintext.as_bytes())?;
        Self::vec_to_key(&decoded)
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

    /// Ask for transit key and returns the provided vault cipher plaintext
    pub fn manually_decrypt_cipher(data_key: &str) -> GenericErr<Vec<u8>> {
        print!("Vault Transit Key: ");
        let vtk_raw: String = text_io::read!();
        log::debug!("Decoding transit key");
        let vtk_bytes = BASE64_STANDARD.decode(vtk_raw)?;
        let vtk_cipher = Aes256Gcm::new(&VaultDataKey::vec_to_key(&vtk_bytes)?);

        log::debug!("Decrypting Cipher - {}", data_key);
        let obj_dk_raw = VaultDataKey::decode_raw_cipher(&data_key)?;
        let obj_iv = *NonceVal::from_slice(&obj_dk_raw.iv);
        match vtk_cipher.decrypt(&obj_iv, obj_dk_raw.data.as_slice()) {
            Ok(v) => Ok(v),
            Err(e) => {
                Err(format!("Failed to decrypt data key - {}", e).into())
            }
        }
    }
}