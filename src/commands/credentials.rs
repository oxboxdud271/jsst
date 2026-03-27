use crate::args::GlobalOpts;
use crate::commands::base::{CredentialConfigData, JSSTCommand};
use crate::util::{get_epoch, GenericErr};
use crate::vault::{VaultClient, VaultClientBuilder};
use clap::{Args, Subcommand};
use serde_json::json;
use std::error::Error;
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
        let output_dir = Path::new(&opts.output);
        let config_path = output_dir.join("credentials.json");
        let cmd = Self {
            commands,
            opts,
            config_path,
        };
        match &cmd.commands.command {
            CliCommandEnum::Bootstrap(a) => cmd.bootstrap(a),
            CliCommandEnum::Show => cmd.show(),
            CliCommandEnum::Refresh(a) => cmd.refresh(a.force),
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
            return Err(app_role["error"]["message"].as_str().unwrap().into());
        }

        log::info!("Retrieving App Role ID...");
        let role_id = client.get(&String::from(format!(
            "/v1/auth/{}/role/{}/role-id",
            auth_mount, machine_id
        )))?;
        if role_id.get("error").is_some() {
            return Err(app_role["error"]["message"].as_str().unwrap().into());
        }
        Ok(String::from(role_id["data"]["role_id"].as_str().unwrap()))
    }

    // Host will not have permission to run this on its own
    fn update_entity(
        &self,
        client: &VaultClient,
        machine_id: Uuid,
        role_id: &String,
        alias_mount: &String,
    ) -> Result<EntityInfo, Box<dyn Error>> {
        log::info!("Retrieving Entity...");
        let entity_lookup = client.post(
            &String::from("/v1/identity/lookup/entity"),
            &json!({
                "alias_name": role_id,
                "alias_mount_accessor": alias_mount
            }),
        )?;
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
            return Err(secret_id["error"]["message"].as_str().unwrap().into());
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

    fn bootstrap(&self, args: &BootstrapArgs) {
        let mut should_bootstrap = false;
        let mut machine_id = Uuid::new_v4();
        let c_time = get_epoch();
        match Self::read_config::<CredentialConfigData>(&self.config_path) {
            Ok(c) => {
                machine_id = c.machine_uuid;
                should_bootstrap = self.refresh_needed(&c)
            }
            Err(e) => {
                log::warn!("Failed to read config: {}", e);
                if !args.force {
                    return;
                }
                should_bootstrap = true;
            }
        }
        log::debug!("Token: {}", args.token);
        log::debug!("Continue Bootstrap?: {}", should_bootstrap);
        if !should_bootstrap && !args.force {
            log::info!("Host already bootstrapped. Exiting.");
            return;
        }
        if args.force {
            log::info!("New bootstrap forced with --force")
        }
        let mut new_data = CredentialConfigData {
            role_id: String::new(),
            secret_id: String::new(),
            secret_id_accessor: String::new(),
            entity_id: String::new(),
            entity_name: String::new(),
            expiration: c_time,
            machine_uuid: machine_id,
            bootstrapped: true,
            auth_mount: args.auth_mount.clone(),
        };

        let client = VaultClientBuilder::new()
            .url(&self.opts.server)
            .token(&args.token)
            .build();
        match client {
            Ok(c) => {
                // Process App Role
                match self.get_role_id(&c, machine_id, &args.auth_mount) {
                    Ok(role_id) => {
                        new_data.role_id = role_id;
                    }
                    Err(e) => {
                        log::error!("Failed to bootstrap App Role: [{}]", e);
                        return;
                    }
                }

                // Process Secret ID
                match self.get_secret_id(&c, machine_id, &args.auth_mount) {
                    Ok(id) => {
                        log::debug!("New Secret ID TTL: {}", id.id_ttl);
                        new_data.secret_id = id.id;
                        new_data.secret_id_accessor = id.accessor;
                        new_data.expiration = c_time + id.id_ttl;
                    }
                    Err(e) => {
                        log::error!("Failed to bootstrap Secret ID: [{}]", e);
                        return;
                    }
                }

                log::debug!("Attempting login with new credentials...");
                // Attempt login to test credentials and create entity info
                match Self::login_to_vault(&self.opts.server, &new_data) {
                    Ok(c) => c,
                    Err(e) => {
                        log::error!("{}", e);
                        return;
                    }
                };

                // Process Entity ID
                match self.update_entity(&c, machine_id, &new_data.role_id, &args.auth_id) {
                    Ok(e) => {
                        new_data.entity_id = e.id;
                        new_data.entity_name = e.name
                    }
                    Err(e) => {
                        log::error!("Failed to bootstrap Entity ID: [{}]", e);
                        return;
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to generate new client: [{}]", e);
                return;
            }
        }

        // Write Config to Disk
        match self.write_config_to_disk(&new_data) {
            Ok(_) => {}
            Err(e) => {
                log::error!("{}", e);
                return;
            }
        }
    }

    fn refresh(&self, force: bool) {
        let c_time = get_epoch();
        match Self::read_config(&self.config_path) {
            Ok(c) => {
                if !self.refresh_needed(&c) && !force {
                    log::info!("Refresh not needed. Use --force to perform action anyway.");
                    return;
                }
                let app_role_client = match Self::login_to_vault(&self.opts.server, &c) {
                    Ok(c) => c,
                    Err(e) => {
                        log::error!("{}", e);
                        return;
                    }
                };
                log::info!("Attempting Secret ID Refresh");
                match self.get_secret_id(&app_role_client, c.machine_uuid, &c.auth_mount) {
                    Ok(s) => {
                        let mut x = c;
                        x.secret_id_accessor = s.accessor;
                        x.secret_id = s.id;
                        x.expiration = c_time + s.id_ttl;
                    }
                    Err(e) => {
                        log::error!("Failed to generate new Secret ID: [{}]", e);
                        return;
                    }
                }
            }
            Err(e) => {
                log::error!("Failed to read config: [{}]", e);
                return;
            }
        }
    }

    fn show(&self) {
        println!("Credentials Show");
    }
}
