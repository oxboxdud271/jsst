use crate::args::GlobalOpts;
use crate::util::get_epoch;
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use uuid::Uuid;

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

    fn bootstrap(&self, args: &BootstrapArgs) {
        let mut should_bootstrap = false;
        let mut bootstrap_success = true;
        let c_time = get_epoch();
        match self.read_config() {
            Ok(c) => {
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
        let new_data = ConfigData {
            role_id: "".to_string(),
            secret_id: "".to_string(),
            expiration: c_time + 100000,
            machine_uuid: Uuid::new_v4(),
            bootstrapped: true,
        };
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
