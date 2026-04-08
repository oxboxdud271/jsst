use clap::{Args, Subcommand, ValueEnum};
use serde_json::json;
use crate::args::GlobalOpts;
use crate::commands::base::{CredentialConfigData, JSSTCommand};
use crate::util::{err_if_standalone, GenericErr};
use crate::data_key::VaultDataKey;

#[derive(Clone, ValueEnum)]
enum DataKeyOutputMode {
    JSON,
    Env,
}

#[derive(Args)]
struct DataKeyArgs {
    #[arg(value_enum)]
    pub mode: DataKeyOutputMode,

    #[arg(long, default_value_t = 256)]
    pub key_size: u32,

    #[arg(long)]
    pub key_name: String
}

#[derive(Args)]
struct GetSecretArgs {
    /// Key of secret
    #[arg(long)]
    pub key: String
}


#[derive(Args)]
struct SaveSecretArgs {
    #[arg(long)]
    pub key: String,

    #[arg(long)]
    pub value: String
}

#[derive(Subcommand)]
enum CliCommandEnum {
    /// Print a Vault data key
    DataKey(DataKeyArgs),

    /// Print a Vault auth token using system credentials
    Login,

    /// Print any secret in Vault KV the machine has access to.
    GetSecret(GetSecretArgs),

    /// Save any secret in Vault
    SaveSecret(SaveSecretArgs)
}

#[derive(Args)]
pub struct UtilityCommandStruct {
    #[command(subcommand)]
    command: CliCommandEnum,
}

pub struct UtilityCommand {
    pub commands: UtilityCommandStruct,
    pub opts: GlobalOpts,
}

impl JSSTCommand<UtilityCommandStruct> for UtilityCommand {
    fn execute(commands: UtilityCommandStruct, opts: GlobalOpts) -> GenericErr {
        let cmd = Self { commands, opts };
        Ok(Self::command_wrapper(
            &cmd,
            &cmd.opts,
            |cmd, cfg| {
                Ok(match &cmd.commands.command {
                    CliCommandEnum::DataKey(a) => Self::get_data_key(cmd, a, cfg)?,
                    CliCommandEnum::Login => Self::login(cmd, cfg)?,
                    CliCommandEnum::GetSecret(a) => Self::get_secret(cmd, a, cfg)?,
                    CliCommandEnum::SaveSecret(a) => Self::save_secret(cmd, a, cfg)?,
                })
            }
        )?)
    }
}
impl UtilityCommand {
    fn login(&self, cfg: &CredentialConfigData) -> GenericErr {
        err_if_standalone(&self.opts.standalone)?;
        let client = Self::login_to_vault(&self.opts, &cfg)?;
        println!("{}", client.token);
        Ok(())
    }

    fn get_data_key(&self, args: &DataKeyArgs, cfg: &CredentialConfigData) -> GenericErr {
        let client = Self::login_to_vault(&self.opts, &cfg)?;
        let data_key = VaultDataKey::retrieve_data_key(&client, &args.key_name, &args.key_size)?;
        match args.mode {
            DataKeyOutputMode::JSON => {
                let json = json!({
                    "plaintext": data_key.plaintext,
                    "ciphertext": data_key.ciphertext
                });
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            }
            DataKeyOutputMode::Env => {
                println!("PLAINTEXT={}", data_key.plaintext);
                println!("CIPHERTEXT={}", data_key.ciphertext);
            }
        }
        Ok(())
    }

    fn get_secret(&self, args: &GetSecretArgs, cfg: &CredentialConfigData) -> GenericErr {
        let client = Self::login_to_vault(&self.opts, &cfg)?;
        let resp = client.get(&format!("/v1/secrets/data/{}", &args.key))?;
        println!("{}", serde_json::to_string(&resp["data"]["data"])?);
        Ok(())
    }

    fn save_secret(&self, args: &SaveSecretArgs, cfg: &CredentialConfigData) -> GenericErr {
        let client = Self::login_to_vault(&self.opts, &cfg)?;
        let key_parts: Vec<&str> = args.key.split("/").collect();
        match key_parts[0] {
            "passwd" => { return Err("passwd is a reserved path".into()); },
            _ => true
        };
        log::info!("Uploading secret - {}", &args.key);
        client.post(
            &format!("/v1/secrets/data/hosts/{}/{}", &cfg.machine_uuid, &args.key),
            &json!({
                "data": {
                    "data": &args.value
                }
            })
        )?;
        Ok(())
    }
}