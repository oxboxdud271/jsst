use crate::args::GlobalOpts;
use crate::util::{get_epoch, GenericErr};
use crate::vault::{VaultClient, VaultClientBuilder};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::path::PathBuf;
use std::{fs, io};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use uuid::Uuid;


#[derive(Serialize, Deserialize, Debug, Default)]
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
    fn execute(commands: C, opts: GlobalOpts) -> GenericErr;

    fn read_config<T: DeserializeOwned>(path: &PathBuf) -> Result<T, Box<dyn Error>> {
        let file = fs::File::open(path)?;
        let reader = io::BufReader::new(file);
        let json = serde_json::from_reader(reader)?;
        Ok(json)
    }

    fn open_file(path: &PathBuf) -> Result<fs::File, Box<dyn Error>> {
        Ok(
            fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?
        )
    }

    fn write_config<T: Serialize>(path: &PathBuf, cfg: &T) -> Result<(), Box<dyn Error>> {
        let file = Self::open_file(path)?;
        let json_string = serde_json::to_string_pretty(cfg)?;
        write!(&file, "{}", json_string)?;
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

    fn login_to_vault(
        opts: &GlobalOpts,
        cfg: &CredentialConfigData,
    ) -> Result<VaultClient, Box<dyn Error>> {
        let mut cb = VaultClientBuilder::new()
            .url(&opts.server)
            .auth_mount(&cfg.auth_mount);

        match &opts.token {
            None => {
                match cb.login(&cfg.role_id, &cfg.secret_id) {
                    Ok(c) => {
                        cb = c
                    }
                    Err(e) => {
                        return Err(format!("Failed to build Vault client: [{}]", e).into())
                    }
                }
            }
            Some(s) => {
                cb = cb.token(&s);
            }
        }
        match cb.build() {
            Ok(c) => Ok(c),
            Err(e) => Err(format!("Failed to build Vault client: [{}]", e).into()),
        }
    }

    /// Will load, verify and login to Vault. It'll execute the `cmd_inner function and print
    /// any errors to stdout.
    fn command_wrapper(
        cmd_self: &Self,
        opts: &GlobalOpts,
        matcher: impl Fn(&Self, &CredentialConfigData) -> GenericErr,
    ) -> GenericErr {
        let mut jsst_path_buf = PathBuf::from(&opts.output);
        jsst_path_buf.push("credentials.json");
        
        let cfg = Self::read_config(&jsst_path_buf)?;
        if !Self::is_credentials_valid(&cfg) {
            return Err("Vault Credentials are invalid / expired. Re-run bootstrap.".into())
        }
        matcher(cmd_self, &cfg)?;
        Ok(())
    }
}
