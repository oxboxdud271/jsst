use std::fs;
use std::path::PathBuf;
use std::process::Command;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use clap::{Args, Subcommand};
use rand::distr::{Alphanumeric, SampleString};
use serde::{Deserialize, Serialize};
use serde_json::json;
use yescrypt::{Yescrypt, PasswordHasher};
use crate::args::GlobalOpts;
use crate::commands::base::{CredentialConfigData, JSSTCommand};
use crate::data_key::VaultDataKey;
use crate::util::{err_if_standalone, json_to_string, GenericErr};
use crate::vault::VaultClient;

#[derive(Args)]
pub struct RotateUserArgs {
    #[arg(long, default_value = "server-admin")]
    username: String,

    #[arg(long)]
    skip_save: bool,
}

#[derive(Args)]
pub struct RotateLuksArgs {
    #[arg(long, default_value = "/dev/sda3")]
    device: String,

    #[arg(long, default_value_t = 0)]
    key_slot: u8,

    #[arg(long)]
    skip_save: bool,
}


#[derive(Args)]
pub struct DecryptArgs {
    #[arg(long)]
    path: String,
}


#[derive(Subcommand)]
pub enum CliCommandEnum {
    /// Rotate Password
    RotateUser(RotateUserArgs),

    /// Rotate LUKS Password
    RotateLUKS(RotateLuksArgs),

    /// Decrypt Password offline
    Decrypt(DecryptArgs),
}

#[derive(Args)]
pub struct PasswdCommandStruct {
    #[command(subcommand)]
    pub command: CliCommandEnum,

}

pub struct PasswdCommand {
    pub cli: PasswdCommandStruct,
    pub opts: GlobalOpts,
}

struct PasswdData {
    hash: String,
    raw: String,
}


#[derive(Serialize, Deserialize)]
struct PasswdStorage {
    cipher: String,
    key: String,
}


impl JSSTCommand<PasswdCommandStruct> for PasswdCommand {
    fn execute(commands: PasswdCommandStruct, opts: GlobalOpts) -> GenericErr {
        let cmd = Self { cli: commands, opts };
        Ok(Self::command_wrapper(
            &cmd,
            &cmd.opts,
            |cmd, cfg| {
                match &cmd.cli.command {
                    CliCommandEnum::RotateUser(a) => Self::rotate_user(cmd, a, cfg),
                    CliCommandEnum::RotateLUKS(a) => Self::rotate_luks(cmd, a, cfg),
                    CliCommandEnum::Decrypt(a) => Self::decrypt(cmd, a),
                }
            }
        )?)
    }
}

impl PasswdCommand {
    fn create_dirs(path: &str) {
        match fs::create_dir_all(&path) {
            Ok(_) => log::debug!("Created directory {}", &path),
            Err(e) => log::warn!("Could not create [{}] ({:?})", path, e),
        }
    }

    fn generate_random_string() -> GenericErr<PasswdData> {
        let yescrypt = Yescrypt::default();

        log::info!("Generating new password");
        let passwd = Alphanumeric.sample_string(&mut rand::rng(), 50);
        let hash = yescrypt.hash_password(&passwd.as_bytes())?;

        Ok(PasswdData {
            raw: passwd,
            hash: String::from(hash.as_str())
        })
    }

    fn upload_to_vault(&self, client: &VaultClient, data: &PasswdData, cfg: &CredentialConfigData, prefix: &str) -> GenericErr {
        log::info!("Uploading new password to Vault");
        client.post(
            &format!("/v1/secrets/data/hosts/{}/{}", &cfg.machine_uuid, prefix),
            &json!({
                "data": {
                    "data": &data.raw,
                    "hash": &data.hash
                }
            })
        )?;
        Ok(())
    }

    fn save_encrypted_data(&self, client: &VaultClient, data: &PasswdData, key: &str, path: &String) -> GenericErr {
        log::info!("Encrypting plaintext");
        let url = format!("/v1/transit/encrypt/{}", key);
        let resp = client.post(
            &String::from(url),
            &json!({
                    "plaintext": BASE64_STANDARD.encode(&data.raw)
                })
        )?;

        let file_data = PasswdStorage {
            cipher: json_to_string(&resp["data"]["ciphertext"]),
            key: String::from(key)
        };

        Self::write_config(&PathBuf::from(path), &file_data)?;
        Ok(())
    }

    fn run_external_command(&self, cmd: &str, args: Vec<&str>) -> GenericErr {
        let cmd_run = Command::new(cmd)
            .args(args)
            .spawn()?;
        let cmd_run_out = cmd_run.wait_with_output()?;
        match cmd_run_out.status.code() {
            None => {
                return Err("Usermod exited by signal. Unknown error".into());
            }
            Some(e) => {
                if e != 0 {
                    return Err(format!("{} exited with error [{}]", cmd, e).into());
                }
                log::info!("{} command exited successfully", cmd);
            }
        }
        Ok(())
    }

    fn rotate_user(&self, args: &RotateUserArgs, cfg: &CredentialConfigData) -> GenericErr {
        err_if_standalone(&self.opts.standalone)?;
        let client = Self::login_to_vault(&self.opts, &cfg)?;
        let new_pass = Self::generate_random_string()?;

        log::info!("Updating {} user", &args.username);
        let cmd_args = vec!["-p", &new_pass.hash, &args.username];
        self.run_external_command("usermod", cmd_args)?;

        let prefix = format!("/passwd/{}", &args.username);
        self.upload_to_vault(&client, &new_pass, &cfg, &prefix)?;

        if !args.skip_save {
            let dir = format!("{}/{}", &self.opts.output, "passwd");
            Self::create_dirs(&dir);

            let file_path = format!("{}/{}", &dir, &args.username);
            self.save_encrypted_data(&client, &new_pass, "jdn-host-passwords", &file_path)?;
        }
        log::info!("Password successfully uploaded");
        Ok(())
    }

    fn rotate_luks(&self, args: &RotateLuksArgs, cfg: &CredentialConfigData) -> GenericErr {
        err_if_standalone(&self.opts.standalone)?;
        let client = Self::login_to_vault(&self.opts, &cfg)?;
        let new_pass = Self::generate_random_string()?;

        log::info!("Updating key slot {}", args.key_slot);
        let secret_prefix = format!("/luks/{}/key-{}", &args.device, &args.key_slot);
        self.upload_to_vault(&client, &new_pass, &cfg, &secret_prefix)?;

        if !args.skip_save {
            let dir = format!("{}/{}/{}", &self.opts.output, "luks", args.device);
            let file_path = format!("{}/key-{}", &dir, &args.key_slot);
            Self::create_dirs(&dir);

            self.save_encrypted_data(&client, &new_pass, "jdn-host-luks", &file_path)?;
        }
        log::info!("LUKS Key successfully uploaded");
        Ok(())
    }

    fn decrypt(&self, args: &DecryptArgs) -> GenericErr {
        let data: PasswdStorage = Self::read_config(&PathBuf::from(&args.path))?;

        log::info!("Decoding password data");
        log::info!("Stored Transit Key: {}", data.key);
        let plaintext = VaultDataKey::manually_decrypt_cipher(&data.cipher)?;
        println!("{}", String::from_utf8(plaintext)?);
        Ok(())
    }
}