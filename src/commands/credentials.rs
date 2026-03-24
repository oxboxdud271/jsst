use crate::args::GlobalOpts;
use crate::util::{get_epoch};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use crate::vault::VaultClient;

#[derive(Args)]
pub struct BootstrapArgs {
    #[arg(short, long)]
    /// Token with sufficient permission to onboard host to Vault
    pub token: String,

    #[arg(short, long)]
    /// Re-bootstrap a existing host
    pub force: bool,
}

#[derive(Args)]
pub struct RefreshArgs {
    #[arg(short, long)]
    /// Force refreshing before it is required
    pub force: bool,
}

#[derive(Subcommand)]
pub enum CliCommandEnum {
    /// Refresh
    Refresh(RefreshArgs),
    /// Display Current Status
    Show,
    /// Onboard Host to Vault
    Bootstrap(BootstrapArgs),
}

#[derive(Args)]
pub struct CredentialsCommandStruct {
    #[command(subcommand)]
    pub command: CliCommandEnum,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConfigData {
    pub role_id: String,
    pub secret_id: String,
    pub secret_id_accessor: String,
    pub expiration: u64,
    pub machine_uuid: Uuid,
    pub bootstrapped: bool,
}

pub struct CredentialsCommand {
    pub commands: CredentialsCommandStruct,
    pub opts: GlobalOpts,
    config_path: PathBuf,
}

impl CredentialsCommand {
    pub fn new(commands: CredentialsCommandStruct, opts: GlobalOpts) -> CredentialsCommand {
        let output_dir = Path::new(&opts.output);
        let config_path = output_dir.join("credentials.json");
        CredentialsCommand {
            commands,
            opts,
            config_path,
        }
    }

    pub fn execute(&self) {
        match &self.commands.command {
            CliCommandEnum::Bootstrap(a) => self.bootstrap(a),
            CliCommandEnum::Show => self.show(),
            CliCommandEnum::Refresh(a) => self.refresh(a.force),
        }
    }

    fn read_config(&self) -> Result<ConfigData, Box<dyn Error>> {
        let file = fs::File::open(&self.config_path)?;
        let reader = io::BufReader::new(file);
        let json = serde_json::from_reader(reader)?;
        Ok(json)
    }

    fn write_config(&self, cfg: &ConfigData) -> Result<(), Box<dyn Error>> {
        let json_string = serde_json::to_string_pretty(cfg)?;
        fs::write(&self.config_path, json_string)?;
        Ok(())
    }

    fn bootstrap_get_role_id(&self, client: VaultClient, machine_id: Uuid) -> Result<String, Box<dyn Error>> {
        println!("Creating / Updating App Role...");
        let app_role = client.post(
            &String::from(format!("/v1/auth/jsst/role/{}", machine_id)),
            &json!({
                "role_name": machine_id.to_string(),
                "bind_secret_id": true,
            })
        )?;
        if !app_role.status().is_success() {
            return Err(app_role.text()?.as_str().into());
        }

        println!("Retrieving App Role ID...");
        let role_id = client.get(
            &String::from(format!("/auth/jsst/role/{}/role-id", machine_id)),
        )?;
        if !role_id.status().is_success() {
            return Err(role_id.text()?.as_str().into());
        }
        let role_id_json: Value = role_id.json()?;
        Ok(String::from(role_id_json["data"]["role_id"].as_str().unwrap()))
    }

    fn bootstrap_get_secret_id(&self, client: VaultClient, machine_id: Uuid) -> Result<String, Box<dyn Error>> {todo!()}

    fn bootstrap(&self, args: &BootstrapArgs) {
        let mut should_bootstrap = false;
        let mut bootstrap_success = true;
        let mut machine_id = Uuid::new_v4();
        let c_time = get_epoch();
        match self.read_config() {
            Ok(c) => {
                machine_id = c.machine_uuid;
                if !c.bootstrapped {
                    should_bootstrap = true;
                }
                if !c.expiration < c_time {
                    should_bootstrap = true;
                }
            }
            Err(_) => {
                should_bootstrap = true;
            }
        }
        if self.opts.verbose {
            println!("Token: {}", args.token);
            println!("Continue Bootstrap?: {}", should_bootstrap);
        }
        if !should_bootstrap && !args.force {
            println!("Host already bootstrapped. Exiting.");
            return;
        }
        if args.force {
            println!("New bootstrap forced with --force")
        }
        let client = VaultClient::new(&self.opts.server.as_str());
        let mut new_data = ConfigData {
            role_id: "".to_string(),
            secret_id: "".to_string(),
            secret_id_accessor: "".to_string(),
            expiration: c_time + 100000,
            machine_uuid: machine_id,
            bootstrapped: true,
        };

        // Process App Role
        match self.bootstrap_get_role_id(client, machine_id) {
            Ok(role_id) => {
                new_data.role_id = role_id;
            }
            Err(e) => {
                println!("Failed to bootstrap App Role: [{}]", e);
                return;
            }
        }

        // Write Config to Disk
        match self.write_config(&new_data) {
            Ok(_) => {
                println!("Successfully wrote config to host");
            }
            Err(e) => {
                println!("Failed to save config to disk: {}", e);
                bootstrap_success = false;
            }
        }
        if !bootstrap_success {
            println!("Failed to completely bootstrap host!")
        }
    }

    fn refresh(&self, force: bool) {
        println!("Credentials Refresh");
    }

    fn show(&self) {
        println!("Credentials Show");
    }
}
