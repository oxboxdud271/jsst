use clap::{Args, Subcommand, ValueEnum};
use serde_json::json;
use crate::args::GlobalOpts;
use crate::commands::base::{CredentialConfigData, JSSTCommand};
use crate::util::{json_to_string, GenericErr};


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

#[derive(Subcommand)]
enum CliCommandEnum {
    /// Retrieve Vault Data Key
    DataKey(DataKeyArgs),

    /// Return a valid Vault token using system credentials
    Login
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
                    CliCommandEnum::Login => Self::login(cmd, cfg)?
                })
            }
        )?)
    }
}
impl UtilityCommand {
    fn login(&self, cfg: &CredentialConfigData) -> GenericErr {
        let client = Self::login_to_vault(&self.opts, &cfg)?;
        println!("{}", client.token);
        Ok(())
    }

    fn get_data_key(&self, args: &DataKeyArgs, cfg: &CredentialConfigData) -> GenericErr {
        let client = Self::login_to_vault(&self.opts, &cfg)?;
        let data_key = client.post(
            &String::from(format!("/v1/transit/datakey/plaintext/{}", &args.key_name)),
            &json!({
                "bits": args.key_size
            })
        )?;
        match args.mode {
            DataKeyOutputMode::JSON => {
                let json = json!({
                    "plaintext": data_key["data"]["plaintext"],
                    "ciphertext": data_key["data"]["ciphertext"]
                });
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            }
            DataKeyOutputMode::Env => {
                println!("PLAINTEXT={}", json_to_string(&data_key["data"]["plaintext"]));
                println!("CIPHERTEXT={}", json_to_string(&data_key["data"]["ciphertext"]));
            }
        }
        Ok(())
    }
}