use std::io::Write;
use std::{fs, io};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use aws_credential_types::Credentials;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;
use crate::util::{get_epoch, json_to_string, GenericErr};
use crate::vault::VaultClient;


#[derive(Serialize, Deserialize)]
pub struct JdnAwsIamCredentials {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,

    #[serde(rename = "Expiration")]
    pub expiration: String,

    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,

    #[serde(rename = "SessionToken")]
    pub session_token: String,

    #[serde(rename = "Version")]
    pub version: i8
}

impl JdnAwsIamCredentials {

    pub fn to_provider(&self) -> Credentials {
        Credentials::from_keys(
            &self.access_key_id,
            &self.secret_access_key,
            Option::from(self.session_token.clone())
        )
    }

    fn get_role_name(machine_id: &Uuid) -> String {
        String::from(format!("host-{}", machine_id))
    }

    fn cache_path(path: &String) -> PathBuf {
        let mut cache_path = PathBuf::from(&path);
        cache_path.push("aws/cred_cache.json");
        cache_path
    }

    fn get_cache_credential(path: &PathBuf) -> GenericErr<JdnAwsIamCredentials> {
        let c_time = DateTime::from_timestamp_secs(get_epoch() as i64).unwrap();
        let file = fs::File::open(path)?;
        let reader = io::BufReader::new(file);
        let json: JdnAwsIamCredentials = serde_json::from_reader(reader)?;
        let cache_expire = json.expiration.parse::<DateTime<Utc>>()?;
        if c_time > cache_expire {
            return Err("Expired".into())
        }
        Ok(json)
    }

    fn get_fresh_aws_keys(client: &VaultClient, machine_uuid: &Uuid) -> GenericErr<JdnAwsIamCredentials> {
        let role_name = Self::get_role_name(&machine_uuid);
        let aws_creds = client.post(
            &String::from(format!("/v1/aws/sts/{}", role_name)),
            &json!({
                "role_session_name": &machine_uuid
            })
        )?;
        let cred_ttl = aws_creds["data"]["ttl"].as_u64().unwrap();
        let dt = DateTime::from_timestamp_secs((get_epoch() + cred_ttl) as i64).unwrap();
        Ok(JdnAwsIamCredentials {
            access_key_id: json_to_string(&aws_creds["data"]["access_key"]),
            expiration: format!("{:?}", dt),
            secret_access_key: json_to_string(&aws_creds["data"]["secret_key"]),
            session_token: json_to_string(&aws_creds["data"]["session_token"]),
            version: 1
        })
    }
    pub fn new(
        client: &VaultClient,
        machine_id: &Uuid,
        jdn_path: &String,
        use_cache: bool,
    ) -> GenericErr<JdnAwsIamCredentials> {
        let cache_path = Self::cache_path(jdn_path);
        if use_cache {
            match Self::get_cache_credential(&cache_path) {
                Ok(c) => {
                    log::info!("Returning cached AWS credentials");
                    return Ok(c);
                }
                Err(e) => {
                    log::info!("AWS Credential Cache miss: [{}]", e)
                }
            }
        }
        let new_creds = Self::get_fresh_aws_keys(&client, machine_id)?;
        if use_cache {
            let file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(cache_path)?;
            let json_string = serde_json::to_string_pretty(&new_creds)?;
            write!(&file, "{}", json_string)?;
        }
        Ok(new_creds)
    }
}