use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use crate::args::GlobalOpts;
use crate::commands::base::{CredentialConfigData, JSSTCommand};
use crate::vault::VaultClient;
use clap::{Args, Subcommand};
use serde_json::{json, Value};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::util::{get_epoch, json_to_string};

#[derive(Args)]
pub struct SetupArgs {
    #[arg(short, long)]
    /// Force re-setup
    pub force: bool
}

#[derive(Args)]
pub struct RetrieveArgs {
    #[arg(long)]
    /// Do not use cache AWS credentials
    pub no_cache: bool
}

#[derive(Subcommand)]
pub enum CliCommandEnum {
    /// Setup AWS Role in Vault
    Setup(SetupArgs),
    /// Retrieve Temporary AWS Credentials
    Retrieve(RetrieveArgs),
}

#[derive(Args)]
pub struct AWSCommandStruct {
    #[command(subcommand)]
    pub command: CliCommandEnum,
}

pub struct AWSCommand {
    pub commands: AWSCommandStruct,
    pub opts: GlobalOpts,
}


#[derive(Serialize, Deserialize)]
pub struct AWSCredentialData {
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


impl JSSTCommand<AWSCommandStruct> for AWSCommand {
    fn execute(commands: AWSCommandStruct, opts: GlobalOpts) -> Self
    {
        match fs::create_dir_all(format!("{}/aws", opts.output)) {
            Ok(_) => {
                log::debug!("Created AWS JSST sub directory")
            }
            Err(e) => {
                log::error!("Failed to create AWS JSST sub directory: [{}]", e)
            }
        }
        let cmd = Self { commands, opts };
        Self::command_wrapper(
            &cmd,
            &cmd.opts,
            |cmd, cfg| {
                match &cmd.commands.command {
                    CliCommandEnum::Setup(args) => Self::setup(cmd, &args, cfg),
                    CliCommandEnum::Retrieve(args) => Self::retrieve(cmd, &args, cfg)
                }
            }
        );
        cmd
    }
}

impl AWSCommand {
    fn get_role_name(machine_id: &Uuid) -> String {
        String::from(format!("host-{}", machine_id))
    }

    fn get_role(client: &VaultClient, machine_id: &Uuid) -> Result<Value, Box<dyn Error>> {
        Ok(client.get(
            &String::from(format!("/v1/aws/roles/{}", Self::get_role_name(machine_id))),
        )?)
    }

    fn setup_role(&self, client: &VaultClient, cfg: &CredentialConfigData) -> Result<Value, Box<dyn Error>> {
        let role_name = Self::get_role_name(&cfg.machine_uuid);
        log::info!("Creating role [{}]...", role_name);
        let setup_role = client.post(
            &String::from(format!("/v1/aws/roles/{}", role_name)),
            &json!({
                "credential_type": "assumed_role",
                "role_arns": [
                    "arn:aws:iam::048780619790:role/VaultHostRole"
                ],
                "session_tags": [
                    {"machine-id": &cfg.machine_uuid}
                ]
            })
        );
        Ok(setup_role?)
    }

    fn create_config_file(&self) -> Result<(), Box<dyn Error>> {
        let mut config_path = PathBuf::from(&self.opts.output);
        config_path.push("aws/config");
        let file = Self::open_file(&config_path)?;
        write!(&file, "[profile host]\ncredential_process=/usr/bin/jsst -q -o {} aws retrieve\n", &self.opts.output)?;
        Ok(())
    }

    fn setup(&self, args: &SetupArgs, cfg: &CredentialConfigData) {
        let client = match Self::login_to_vault(&self.opts.server, &cfg) {
            Ok(c) => c,
            Err(e) => {
                log::error!("{}", e);
                return;
            }
        };
        match Self::get_role(&client, &cfg.machine_uuid) {
            Ok(_) => {
                if !args.force {
                    log::info!("Role already exists in the Vault. Use --force to re-create");
                    return;
                }
            }
            Err(_) => {
                log::info!("Role does not exist")
            }
        }
        match self.setup_role(&client, cfg) {
            Ok(_) => {
                log::info!("Role created successfully");
            }
            Err(e) => {
                log::error!("Role creation failed: [{}]", e)
            }
        }
        match self.create_config_file() {
            Ok(_) => {
                log::info!("AWS config created successfully");
            }
            Err(e) => {
                log::error!("Create config file failed: [{}]", e)
            }
        }
    }

    fn get_cache_credential(&self, path: &PathBuf) -> Result<AWSCredentialData, Box<dyn Error>> {
        let c_time = DateTime::from_timestamp_secs(get_epoch() as i64).unwrap();
        let cfg = Self::read_config::<AWSCredentialData>(&path)?;
        let cache_expire = cfg.expiration.parse::<DateTime<Utc>>()?;
        if c_time > cache_expire {
            return Err("Expired".into())
        }
        Ok(cfg)
    }


    fn retrieve(&self, args: &RetrieveArgs, cfg: &CredentialConfigData) {
        let mut cache_path = PathBuf::from(&self.opts.output);
        cache_path.push("aws/cred_cache.json");
        match self.get_cache_credential(&cache_path) {
            Ok(data) => {
                if !args.no_cache {
                    log::info!("Returning cached AWS credentials");
                    println!("{}", serde_json::to_string_pretty(&data).unwrap());
                    return;
                } else {
                    log::info!("Ignoring cache.")
                }
            }
            Err(e) => {
                log::info!("Cache miss: [{}]", e)
            }
        }
        let client = match Self::login_to_vault(&self.opts.server, &cfg) {
            Ok(c) => c,
            Err(e) => {
                log::error!("{}", e);
                return;
            }
        };
        let role_name = Self::get_role_name(&cfg.machine_uuid);
        let get_credentials = client.post(
            &String::from(format!("/v1/aws/sts/{}", role_name)),
            &json!({
                "role_session_name": &cfg.machine_uuid
            })
        );
        match get_credentials {
            Ok(creds) => {
                let cred_ttl = creds["data"]["ttl"].as_u64().unwrap();
                let dt = DateTime::from_timestamp_secs((get_epoch() + cred_ttl) as i64).unwrap();
                let new_creds = AWSCredentialData {
                    access_key_id: json_to_string(&creds["data"]["access_key"]),
                    expiration: format!("{:?}", dt),
                    secret_access_key:  json_to_string(&creds["data"]["secret_key"]),
                    session_token:  json_to_string(&creds["data"]["session_token"]),
                    version: 1,
                };
                match Self::write_config(&cache_path, &new_creds) {
                    Ok(_) => {
                        log::info!("Successfully cached AWS Credentials.");
                    }
                    Err(e) => {
                        log::warn!("Failed to cache AWS Credentials: [{}]", e)
                    }
                }
                // Always print this to stdout regardless of logging level
                println!("{}", serde_json::to_string_pretty(&new_creds).unwrap());
            }
            Err(e) => {
                log::error!("Failed to retrieve credentials: [{}]", e);
            }
        }
    }
}
