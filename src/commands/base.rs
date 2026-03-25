use crate::args::GlobalOpts;
use crate::util::get_epoch;
use crate::vault::{VaultClient, VaultClientBuilder};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::path::PathBuf;
use std::{fs, io};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
pub struct CredentialConfigData {
    pub role_id: String,
    pub secret_id: String,
    pub secret_id_accessor: String,
    pub expiration: u64,
    pub machine_uuid: Uuid,
    pub bootstrapped: bool,
    pub entity_id: String,
    pub entity_name: String,
    pub auth_mount: String,
}

pub trait JSSTCommand<C> {
    fn execute(commands: C, opts: GlobalOpts) -> Self;

    fn read_config<T: DeserializeOwned>(path: &PathBuf) -> Result<T, Box<dyn Error>> {
        let file = fs::File::open(path)?;
        let reader = io::BufReader::new(file);
        let json = serde_json::from_reader(reader)?;
        Ok(json)
    }

    fn write_config<T: Serialize>(path: &PathBuf, cfg: &T) -> Result<(), Box<dyn Error>> {
        let json_string = serde_json::to_string_pretty(cfg)?;
        fs::write(path, json_string)?;
        Ok(())
    }

    fn is_credentials_valid(cfg: &CredentialConfigData) -> bool {
        let c_time = get_epoch();
        let mut valid: bool = true;
        if !cfg.bootstrapped {
            valid = false;
        }
        let diff = cfg.expiration - c_time;
        if diff <= 0 {
            valid = false;
        }
        valid
    }

    fn refresh_needed(cfg: &CredentialConfigData) -> bool {
        if !Self::is_credentials_valid(cfg) {
            return true;
        }
        let c_time = get_epoch();
        if cfg.expiration - c_time < 259200 {
            true;
        }
        false
    }

    fn login_to_vault(
        url: &String,
        cfg: &CredentialConfigData,
    ) -> Result<VaultClient, Box<dyn Error>> {
        let app_role_client_builder = VaultClientBuilder::new()
            .url(url)
            .auth_mount(&cfg.auth_mount)
            .login(&cfg.role_id, &cfg.secret_id);

        match app_role_client_builder {
            Ok(c) => match c.build() {
                Ok(c) => Ok(c),
                Err(e) => Err(format!("Failed to build Vault client: [{}]", e).into()),
            },
            Err(e) => Err(format!("Failed to build Vault client: [{}]", e).into()),
        }
    }

    /// Will load, verify and login to Vault. It'll execute the `cmd_inner function and print
    /// any errors to stdout.
    fn command_wrapper(
        cmd_self: &Self,
        jsst_path: &String,
        vault_url: &String,
        matcher: impl Fn(&Self, &VaultClient),
    ) {
        let jsst_path_buf = PathBuf::from(jsst_path);
        match Self::read_config(&jsst_path_buf) {
            Ok(cfg) => {
                if !Self::is_credentials_valid(&cfg) {
                    print!("Vault Credentials are invalid / expired. Re-run bootstrap.");
                    return;
                }
                match Self::login_to_vault(vault_url, &cfg) {
                    Ok(client) => {
                        println!("Successfully logged in with {}", &cfg.role_id);
                        matcher(cmd_self, &client);
                    }
                    Err(e) => {
                        println!("{}", e);
                    }
                }
            }
            Err(e) => {
                println!("{}", e);
            }
        }
    }
}
