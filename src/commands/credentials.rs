use crate::args::GlobalOpts;
use crate::commands::base::{CredentialConfigData, JSSTCommand};
use crate::util::{err_if_standalone, get_epoch, GenericErr};
use crate::vault::{VaultClient, VaultClientBuilder};
use clap::{Args, Subcommand};
use serde_json::json;
use std::error::Error;
use std::io::Error as IoError;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Args)]
pub struct BootstrapArgs {
    #[arg(short, long)]
    /// Re-bootstrap a existing host
    pub force: bool,

    #[arg(long)]
    /// Auth mount ID
    pub auth_id: String,

    #[arg(long, default_value = "jsst")]
    /// Auth mount location
    pub auth_mount: String,
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

pub struct CredentialsCommand {
    pub commands: CredentialsCommandStruct,
    pub opts: GlobalOpts,
    config_path: PathBuf,
}

struct SecretIDPair {
    id: String,
    id_ttl: u64,
    accessor: String,
}

struct EntityInfo {
    id: String,
    name: String,
}

impl JSSTCommand<CredentialsCommandStruct> for CredentialsCommand {
    fn execute(commands: CredentialsCommandStruct, opts: GlobalOpts) -> GenericErr {
        err_if_standalone(&opts.standalone)?;
        let output_dir = Path::new(&opts.output);
        let config_path = output_dir.join("credentials.json");
        let token = opts.token.clone();
        let cmd = Self {
            commands,
            opts,
            config_path,
        };
        match &cmd.commands.command {
            CliCommandEnum::Bootstrap(a) => {
                match {token} {
                    None => {log::error!("Missing token for bootstrap");}
                    Some(t) => cmd.bootstrap(a, &t)
                }
            },
            CliCommandEnum::Show => cmd.show(),
            CliCommandEnum::Refresh(a) => cmd.refresh(a.force)?,
        }
        Ok(())
    }
}

impl CredentialsCommand {
    // Host will not have permission to run this on its own
    fn get_role_id(
        &self,
        client: &VaultClient,
        machine_id: Uuid,
        auth_mount: &String,
    ) -> Result<String, Box<dyn Error>> {
        log::info!("Creating / Updating App Role...");
        let app_role = client.post(
            &String::from(format!("/v1/auth/{}/role/{}", auth_mount, machine_id)),
            &json!({
                "role_name": machine_id.to_string(),
                "bind_secret_id": true,
                "secret_id_ttl": 1296000
            }),
        )?;
        if app_role.get("error").is_some() {
            return Err(format!("{}", app_role["error"]["message"]).into())
        }

        log::info!("Retrieving App Role ID...");
        let role_id = client.get(&String::from(format!(
            "/v1/auth/{}/role/{}/role-id",
            auth_mount, machine_id
        )))?;
        if role_id.get("error").is_some() {
            return Err(format!("{}", role_id["error"]["message"]).into())
        }
        Ok(String::from(role_id["data"]["role_id"].as_str().unwrap()))
    }

    // Host will not have permission to run this on its own
    fn update_entity(
        &self,
        client: &VaultClient,
        machine_id: Uuid,
        role_id: &String,
        auth_id: &String,
    ) -> GenericErr<EntityInfo> {
        log::info!("Retrieving Entity...");
        let entity_lookup = client.post(
            &String::from("/v1/identity/lookup/entity"),
            &json!({
                "alias_name": role_id,
                "alias_mount_accessor": auth_id
            }),
        )?;
        log::debug!("Entity Info: {}", entity_lookup);
        if entity_lookup.get("data").is_none() {
            return Err(Box::from("Entity lookup returned no results"))
        }

        let entity_info = EntityInfo {
            id: String::from(entity_lookup["data"]["id"].as_str().unwrap()),
            name: String::from(entity_lookup["data"]["name"].as_str().unwrap()),
        };

        log::info!("Updating Entity Metadata...");
        let update_entity_metadata = client.post(
            &String::from(format!("/v1/identity/entity/id/{}", entity_info.id)),
            &json!({
                "metadata": {
                    "role-id": role_id,
                    "machine-id": machine_id
                }
            }),
        )?;
        if update_entity_metadata.get("error").is_some() {
            return Err(update_entity_metadata["error"]["message"]
                .as_str()
                .unwrap()
                .into());
        }
        Ok(entity_info)
    }

    fn get_secret_id(
        &self,
        client: &VaultClient,
        machine_id: Uuid,
        auth_mount: &String,
    ) -> Result<SecretIDPair, Box<dyn Error>> {
        log::info!("Creating Secret ID...");
        let secret_id = client.post(
            &String::from(format!(
                "/v1/auth/{}/role/{}/secret-id",
                auth_mount, machine_id
            )),
            &json!({ "secret_id": machine_id }),
        )?; 
        if secret_id.get("error").is_some() {
            return Err(format!("{}", secret_id["error"]["message"]).into())
        }
        Ok(SecretIDPair {
            id: String::from(secret_id["data"]["secret_id"].as_str().unwrap()),
            id_ttl: secret_id["data"]["secret_id_ttl"].as_u64().unwrap(),
            accessor: String::from(secret_id["data"]["secret_id_accessor"].as_str().unwrap()),
        })
    }

    fn write_config_to_disk(&self, cfg: &CredentialConfigData) -> Result<(), Box<dyn Error>> {
        match Self::write_config(&self.config_path, &cfg) {
            Ok(_) => {
                log::info!("Successfully wrote config to host");
                Ok(())
            }
            Err(e) => Err(format!("Failed to save config to disk: {}", e).into()),
        }
    }

    fn refresh_needed(&self, cfg: &CredentialConfigData) -> bool {
        let c_time = get_epoch();
        let mut refresh: bool = false;
        if !cfg.bootstrapped {
            refresh = true;
        }
        let diff = cfg.expiration - c_time;
        if diff == 0 || diff < 259200 {
            refresh = true;
        }
        refresh
    }

    fn run_bootstrap(&self, cfg: &mut CredentialConfigData, args: &BootstrapArgs, token: &String) -> GenericErr {
        let c_time = get_epoch();
        let client = VaultClientBuilder::new().token(&token).build()?;

        // Process App Role
        if cfg.role_id.is_empty() {
            cfg.role_id = self.get_role_id(&client, cfg.machine_uuid, &args.auth_mount)?;
        } else {
            log::info!("Role ID already present in config. Skipping...");
        }

        // Process Secret ID
        if cfg.secret_id.is_empty() {
            let secret_data = self.get_secret_id(&client, cfg.machine_uuid, &args.auth_mount)?;
            log::debug!("New Secret ID TTL: {}", secret_data.id_ttl);
            cfg.secret_id = secret_data.id;
            cfg.secret_id_accessor = secret_data.accessor;
            cfg.expiration = c_time + secret_data.id_ttl;
        } else {
            log::info!("Secret ID already present in config. Skipping...");
        }


        log::info!("Attempting login with new credentials...");
        // Attempt login to test credentials and create entity info
        VaultClientBuilder::new().login(&cfg.role_id, &cfg.secret_id)?;

        // Process Entity ID
        let entity_data = self.update_entity(&client, cfg.machine_uuid, &cfg.role_id, &args.auth_id)?;
        cfg.entity_id = entity_data.id;
        cfg.entity_name = entity_data.name;

        Ok(())
    }

    fn bootstrap(&self, args: &BootstrapArgs, token: &String) {
        let mut cfg = match Self::read_config::<CredentialConfigData>(&self.config_path) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("Failed to read config: {}", e);
                let last_error = IoError::last_os_error();
                match last_error.kind() {
                    std::io::ErrorKind::PermissionDenied => {
                        log::error!("Insufficient permissions to read config");
                        return;
                    }
                    _ => log::warn!("Failed to read config: {}", e)
                }
                let new_cfg = CredentialConfigData {
                    machine_uuid: Uuid::new_v4(),
                    ..Default::default()
                };
                new_cfg
            }
        };

        let mut need_bootstrap = false;
        let c_time = get_epoch();
        if !cfg.bootstrapped {
            need_bootstrap = true
        }
        if cfg.expiration - c_time <= 0 {
            need_bootstrap = true;
        }
        if !need_bootstrap && !args.force {
            log::info!("Host already bootstrapped. Exiting.");
            return;
        }
        if args.force {
            log::info!("New bootstrap forced with --force");

            // Re-use the machine UUID
            cfg =  CredentialConfigData {
                machine_uuid: cfg.machine_uuid,
                ..Default::default()
            };
        }

        log::info!("Machine ID: {}", &cfg.machine_uuid);
        match self.run_bootstrap(&mut cfg, &args, token) {
            Ok(_) => {
                cfg.auth_mount = args.auth_mount.clone();
                cfg.bootstrapped = true
            }
            Err(e) => {
                log::error!("Failed bootstrap: {}", e);
                log::info!("Bootstrap failed. Writing existing data to disk!");
            }
        }

        // Write Config to Disk
        match self.write_config_to_disk(&cfg) {
            Ok(_) => {}
            Err(e) => {
                log::error!("{}", e);
                return;
            }
        }
    }

    fn refresh(&self, force: bool) -> GenericErr {
        let c_time = get_epoch();
        let cfg = Self::read_config(&self.config_path)?;
        if !self.refresh_needed(&cfg) && !force {
            log::info!("Refresh not needed. Use --force to perform action anyway.");
            return Ok(())
        }
        let app_role_client = Self::login_to_vault(&self.opts, &cfg)?;
        log::info!("Attempting Secret ID Refresh");
        let sid = self.get_secret_id(&app_role_client, cfg.machine_uuid, &cfg.auth_mount)?;
        let mut x = cfg;
        x.secret_id_accessor = sid.accessor;
        x.secret_id = sid.id;
        x.expiration = c_time + sid.id_ttl;
        self.write_config_to_disk(&x)?;
        Ok(())
    }

    fn show(&self) {
        println!("Credentials Show");
    }
}
