use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use crate::args::GlobalOpts;
use crate::commands::base::{CredentialConfigData, JSSTCommand};
use crate::vault::VaultClient;
use clap::{Args, Subcommand};
use serde_json::{json, Value};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::util::{get_epoch, json_to_string, GenericErr};

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

#[derive(Args)]
pub struct RunArgs {
    #[arg(trailing_var_arg = true)]
    cmd: Vec<String>,
}

#[derive(Subcommand)]
pub enum CliCommandEnum {
    /// Setup AWS Role in Vault
    Setup(SetupArgs),
    /// Output temporary AWS credentials to stdout
    Retrieve(RetrieveArgs),
    /// Run command with AWS certs in Environment
    Run(RunArgs),
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
    fn execute(commands: AWSCommandStruct, opts: GlobalOpts) -> GenericErr
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
        Ok(Self::command_wrapper(
            &cmd,
            &cmd.opts,
            |cmd, cfg| {
                Ok(match &cmd.commands.command {
                    CliCommandEnum::Setup(a) => Self::setup(cmd, &a, cfg)?,
                    CliCommandEnum::Retrieve(a) => Self::retrieve(cmd, &a, cfg),
                    CliCommandEnum::Run(a) => Self::run(cmd, &a, cfg)?
                })
            }
        )?)
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

    fn setup(&self, args: &SetupArgs, cfg: &CredentialConfigData) -> GenericErr {
        let client = Self::login_to_vault(&self.opts, &cfg)?;
        match Self::get_role(&client, &cfg.machine_uuid) {
            Ok(_) => {
                if !args.force {
                    log::info!("Role already exists in the Vault. Use --force to re-create");
                    return Ok(());
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
                return Err(format!("Role creation failed: [{}]", e).into());
            }
        }
        match self.create_config_file() {
            Ok(_) => {
                log::info!("AWS config created successfully");
            }
            Err(e) => {
                return Err(format!("Create config file failed: [{}]", e).into());
            }
        }
        Ok(())
    }

    fn get_cache_credential(path: &PathBuf) -> Result<AWSCredentialData, Box<dyn Error>> {
        let c_time = DateTime::from_timestamp_secs(get_epoch() as i64).unwrap();
        let cfg = Self::read_config::<AWSCredentialData>(&path)?;
        let cache_expire = cfg.expiration.parse::<DateTime<Utc>>()?;
        if c_time > cache_expire {
            return Err("Expired".into())
        }
        Ok(cfg)
    }

    fn cache_path(path: &String) -> PathBuf {
        let mut cache_path = PathBuf::from(&path);
        cache_path.push("aws/cred_cache.json");
        cache_path
    }

    pub fn get_fresh_aws_keys(client: &VaultClient, machine_uuid: &Uuid) -> GenericErr<AWSCredentialData> {
        let role_name = Self::get_role_name(&machine_uuid);
        let aws_creds = client.post(
            &String::from(format!("/v1/aws/sts/{}", role_name)),
            &json!({
                "role_session_name": &machine_uuid
            })
        )?;
        let cred_ttl = aws_creds["data"]["ttl"].as_u64().unwrap();
        let dt = DateTime::from_timestamp_secs((get_epoch() + cred_ttl) as i64).unwrap();
        Ok(AWSCredentialData {
            access_key_id: json_to_string(&aws_creds["data"]["access_key"]),
            expiration: format!("{:?}", dt),
            secret_access_key:  json_to_string(&aws_creds["data"]["secret_key"]),
            session_token:  json_to_string(&aws_creds["data"]["session_token"]),
            version: 1,
        })
    }

    fn get_credentials(&self, cfg: &CredentialConfigData, use_cache: bool) -> GenericErr<AWSCredentialData> {
        let cache_path = Self::cache_path(&self.opts.output);
        match Self::get_cache_credential(&cache_path) {
            Ok(data) => {
                if use_cache {
                    log::info!("Returning cached AWS credentials");
                    return Ok(data);
                } else {
                    log::info!("Ignoring cache.")
                }
            }
            Err(e) => {
                log::info!("Cache miss: [{}]", e)
            }
        }
        let client = Self::login_to_vault(&self.opts, &cfg)?;
        let new_creds = Self::get_fresh_aws_keys(&client, &cfg.machine_uuid)?;
        match Self::write_config(&cache_path, &new_creds) {
            Ok(_) => {
                log::info!("Successfully cached AWS Credentials.");
            }
            Err(e) => {
                log::warn!("Failed to cache AWS Credentials: [{}]", e)
            }
        }
        Ok(new_creds)
    }

    fn retrieve(&self, args: &RetrieveArgs, cfg: &CredentialConfigData) {
        match self.get_credentials(cfg, !args.no_cache) {
            Ok(creds) => {
                // Always print this to stdout regardless of logging level
                println!("{}", serde_json::to_string_pretty(&creds).unwrap());
            }
            Err(e) => log::warn!("Failed to retrieve credentials: [{}]", e)
        }
    }

    fn start_cmd_process(creds: &AWSCredentialData, cmd: &Vec<String>) -> Result<(), Box<dyn Error>>   {
        let new_process = Command::new(&cmd[0])
            .args(&cmd[1..])
            .stdout(Stdio::inherit())
            .env("AWS_ACCESS_KEY_ID", &creds.access_key_id)
            .env("AWS_SECRET_ACCESS_KEY", &creds.secret_access_key)
            .env("AWS_SESSION_TOKEN", &creds.session_token)
            .spawn()?;
        new_process.wait_with_output()?;
        Ok(())
    }

    fn run(&self, args: &RunArgs, cfg: &CredentialConfigData) -> GenericErr {
        let creds =  self.get_credentials(cfg, true)?;
        log::info!("Command: {:?}", args.cmd);
        Self::start_cmd_process(&creds, &args.cmd)?;
        Ok(())
    }
}
