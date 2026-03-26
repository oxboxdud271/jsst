use std::error::Error;
use crate::args::GlobalOpts;
use crate::commands::base::{CredentialConfigData, JSSTCommand};
use crate::vault::VaultClient;
use clap::{Args, Subcommand};
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Args)]
pub struct SetupArgs {
    #[arg(short, long)]
    /// Force re-setup
    pub force: bool
}

#[derive(Subcommand)]
pub enum CliCommandEnum {
    /// Setup AWS Role in Vault
    Setup(SetupArgs),
    /// Retrieve Temporary AWS Credentials
    Retrieve,
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


impl JSSTCommand<AWSCommandStruct> for AWSCommand {
    fn execute(commands: AWSCommandStruct, opts: GlobalOpts) -> Self
    {
        let cmd = Self { commands, opts };
        Self::command_wrapper(
            &cmd,
            &cmd.opts.output,
            &cmd.opts.server,
            |a, b, c| {
                match &a.commands.command {
                    CliCommandEnum::Setup(args) => Self::setup(a, b, &args, c),
                    CliCommandEnum::Retrieve => Self::retrieve(a, b, c)
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
        println!("Creating role [{}]...", role_name);
        let setup_role = client.post(
            &String::from(format!("/v1/aws/roles/{}", role_name)),
            &json!({
                "credential_type": "assumed_role",
                "role_arns": [
                    "arn:aws:iam::048780619790:role/VaultHostRole"
                ]
            })
        );
        Ok(setup_role?)
    }

    fn setup(&self, client: &VaultClient, args: &SetupArgs, cfg: &CredentialConfigData) {
        match Self::get_role(client, &cfg.machine_uuid) {
            Ok(_) => {
                if !args.force {
                    println!("Role already exists in the Vault. Use --force to re-create");
                    return;
                }
            }
            Err(_) => {
                println!("Role does not exist")
            }
        }
        match self.setup_role(client, cfg) {
            Ok(_) => {
                println!("Role created successfully");
            }
            Err(e) => {
                println!("Role creation failed: [{}]", e)
            }
        }
    }

    fn retrieve(&self, client: &VaultClient, cfg: &CredentialConfigData) {
        let role_name = Self::get_role_name(&cfg.machine_uuid);
        let get_credentials = client.post(
            &String::from(format!("/v1/aws/sts/{}", role_name)),
            &json!({
                "role_session_name": &cfg.machine_uuid
            })
        );
        match get_credentials {
            Ok(creds) => {
                let cli_creds = json!({
                    "Version": 1,
                    "AccessKeyId": creds["data"]["access_key"],
                    "SecretAccessKey": creds["data"]["secret_key"],
                    "SessionToken": creds["data"]["session_token"],
                    "Expiration": "",
                });
                println!("{}", serde_json::to_string_pretty(&cli_creds).unwrap());
            }
            Err(e) => {
                println!("Failed to retrieve credentials: [{}]", e);
            }
        }
    }
}
