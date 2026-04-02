use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use clap::{Args, Subcommand};
use rand::distr::{Alphanumeric, SampleString};
use serde_json::json;
use yescrypt::{Yescrypt, PasswordHasher};
use crate::args::GlobalOpts;
use crate::commands::base::{CredentialConfigData, JSSTCommand};
use crate::data_key::VaultDataKey;
use crate::util::{err_if_standalone, GenericErr};


#[derive(Args)]
pub struct RotateArgs {
    #[arg(long)]
    skip_save: bool,
}


#[derive(Subcommand)]
pub enum CliCommandEnum {
    /// Rotate Password
    Rotate(RotateArgs),

    /// Decrypt Password offline
    Decrypt
}

#[derive(Args)]
pub struct PasswdCommandStruct {
    #[command(subcommand)]
    pub command: CliCommandEnum,

    #[arg(long, default_value = "server-admin")]
    username: String,
}

pub struct PasswdCommand {
    pub cli: PasswdCommandStruct,
    pub opts: GlobalOpts,
}

impl JSSTCommand<PasswdCommandStruct> for PasswdCommand {
    fn execute(commands: PasswdCommandStruct, opts: GlobalOpts) -> GenericErr {
        let cmd = Self { cli: commands, opts };
        Ok(Self::command_wrapper(
            &cmd,
            &cmd.opts,
            |cmd, cfg| {
                match &cmd.cli.command {
                    CliCommandEnum::Rotate(a) => Self::rotate(cmd, a, cfg),
                    CliCommandEnum::Decrypt => Self::decrypt(cmd),
                }
            }
        )?)
    }
}

impl PasswdCommand {
    fn pass_file_location(&self) -> PathBuf {
        format!("{}passwd/{}", &self.opts.output, &self.cli.username).into()
    }

    fn rotate(&self, args: &RotateArgs, cfg: &CredentialConfigData) -> GenericErr {
        err_if_standalone(&self.opts.standalone)?;
        let client = Self::login_to_vault(&self.opts, &cfg)?;
        let yescrypt = Yescrypt::default();

        log::info!("Generating new password");
        let passwd = Alphanumeric.sample_string(&mut rand::rng(), 50);
        let hash = yescrypt.hash_password(&passwd.as_bytes())?;

        log::info!("Updating {} user", &self.cli.username);
        let usermod = Command::new("usermod")
            .arg("-p")
            .arg(hash.as_str())
            .arg(&self.cli.username)
            .spawn()?;
        let usermod_out = usermod.wait_with_output()?;
        match usermod_out.status.code() {
            None => {
                return Err("Usermod exited by signal. Unknown error".into());
            }
            Some(e) => {
                if e != 0 {
                    return Err(format!("Usermod exited with error [{}]", e).into());
                }
                log::info!("Usermod command exited successfully");
            }
        }
        log::info!("Uploading new password to Vault");
        client.post(
            &format!("/v1/host-passwd-kv/data/{}/{}", &cfg.machine_uuid, &self.cli.username),
            &json!({
                "data": {
                    "passwd": passwd,
                    "host_hash": hash.as_str()
                }
            })
        )?;
        if !args.skip_save {
            log::info!("Encrypting plaintext");
            let resp = client.post(
                &String::from("/v1/transit/encrypt/jdn-host-backup"),
                &json!({
                    "plaintext": BASE64_STANDARD.encode(&passwd)
                })
            )?;

            let ciphertext = resp["data"]["ciphertext"].as_str().unwrap().as_bytes();
            let mut file = Self::open_file(&self.pass_file_location())?;
            file.write(ciphertext)?;
        }
        log::info!("Password successfully uploaded");
        Ok(())
    }

    fn decrypt(&self) -> GenericErr {
        let file_path = self.pass_file_location();
        log::info!("Reading file - {:?}", file_path);

        let mut file = fs::File::open(&file_path)?;
        let mut buffer = String::new();
        file.read_to_string(&mut buffer)?;

        log::info!("Decoding password data");
        let plaintext = VaultDataKey::manually_decrypt_cipher(&buffer)?;
        println!("{}", String::from_utf8(plaintext)?);
        Ok(())
    }
}