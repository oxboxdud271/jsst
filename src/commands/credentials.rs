use crate::args::GlobalOpts;
use crate::util::get_epoch;
use crate::vault::{VaultClient, VaultClientBuilder};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::json;
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

#[derive(Serialize, Deserialize, Debug)]
pub struct ConfigData {
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

    // Host will not have permission to run this on its own
    fn get_role_id(
        &self,
        client: &VaultClient,
        machine_id: Uuid,
        auth_mount: &String,
    ) -> Result<String, Box<dyn Error>> {
        println!("Creating / Updating App Role...");
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

        println!("Retrieving App Role ID...");
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
        println!("Retrieving Entity...");
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

        println!("Updating Entity Metadata...");
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
        println!("Creating Secret ID...");
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

    fn build_vault_client(
        &self,
        role_id: &String,
        secret_id: &String,
        url: &String,
        auth_mount: &String,
    ) -> Result<VaultClient, Box<dyn Error>> {
        let app_role_client_builder = VaultClientBuilder::new()
            .url(url)
            .auth_mount(auth_mount)
            .login(role_id, secret_id);

        match app_role_client_builder {
            Ok(c) => match c.build() {
                Ok(c) => {
                    println!("Successfully logged in with {}", role_id);
                    Ok(c)
                }
                Err(e) => Err(format!("Failed to build app role client: [{}]", e).into()),
            },
            Err(e) => Err(format!("Failed to build app role client: [{}]", e).into()),
        }
    }

    fn write_config_to_disk(&self, cfg: &ConfigData) -> Result<(), Box<dyn Error>> {
        match self.write_config(&cfg) {
            Ok(_) => {
                println!("Successfully wrote config to host");
                Ok(())
            }
            Err(e) => Err(format!("Failed to save config to disk: {}", e).into()),
        }
    }

    fn refresh_needed(&self, cfg: &ConfigData) -> bool {
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
        match self.read_config() {
            Ok(c) => {
                machine_id = c.machine_uuid;
                should_bootstrap = self.refresh_needed(&c)
            }
            Err(e) => {
                println!("Failed to read config: {}", e);
                if !args.force {
                    return;
                }
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
        let mut new_data = ConfigData {
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
                        println!("Failed to bootstrap App Role: [{}]", e);
                        return;
                    }
                }

                // Process Secret ID
                match self.get_secret_id(&c, machine_id, &args.auth_mount) {
                    Ok(id) => {
                        println!("New Secret ID TTL: {}", id.id_ttl);
                        new_data.secret_id = id.id;
                        new_data.secret_id_accessor = id.accessor;
                        new_data.expiration = c_time + id.id_ttl;
                    }
                    Err(e) => {
                        println!("Failed to bootstrap Secret ID: [{}]", e);
                        return;
                    }
                }

                println!("Attempting login with new credentials...");
                // Attempt login to test credentials and create entity info
                match self.build_vault_client(
                    &new_data.role_id,
                    &new_data.secret_id,
                    &self.opts.server,
                    &args.auth_mount,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        println!("{}", e);
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
                        println!("Failed to bootstrap Entity ID: [{}]", e);
                        return;
                    }
                }
            }
            Err(e) => {
                println!("Failed to generate new client: [{}]", e);
                return;
            }
        }

        // Write Config to Disk
        match self.write_config_to_disk(&new_data) {
            Ok(_) => {}
            Err(e) => {
                println!("{}", e);
                return;
            }
        }
    }

    fn refresh(&self, force: bool) {
        let c_time = get_epoch();
        match self.read_config() {
            Ok(c) => {
                if !self.refresh_needed(&c) && !force {
                    println!("Refresh not needed. Use --force to perform action anyway.");
                    return;
                }
                let app_role_client = match self.build_vault_client(
                    &c.role_id,
                    &c.secret_id,
                    &self.opts.server,
                    &c.auth_mount,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        println!("{}", e);
                        return;
                    }
                };
                println!("Attempting Secret ID Refresh");
                match self.get_secret_id(&app_role_client, c.machine_uuid, &c.auth_mount) {
                    Ok(s) => {
                        let mut x = c;
                        x.secret_id_accessor = s.accessor;
                        x.secret_id = s.id;
                        x.expiration = c_time + s.id_ttl;
                    }
                    Err(e) => {
                        println!("Failed to generate new Secret ID: [{}]", e);
                        return;
                    }
                }
            }
            Err(e) => {
                println!("Failed to read config: [{}]", e);
                return;
            }
        }
    }

    fn show(&self) {
        println!("Credentials Show");
    }
}
