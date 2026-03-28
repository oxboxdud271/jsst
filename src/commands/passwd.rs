use std::process::Command;
use clap::{Args, Subcommand};
use rand::distr::{Alphanumeric, SampleString};
use serde_json::json;
use yescrypt::{Yescrypt, PasswordHasher};
use crate::args::GlobalOpts;
use crate::commands::base::{CredentialConfigData, JSSTCommand};
use crate::util::GenericErr;

#[derive(Subcommand)]
pub enum CliCommandEnum {
    /// Rotate Password
    Rotate
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
                    CliCommandEnum::Rotate => Self::rotate(cmd, cfg)
                }
            }
        )?)
    }
}

impl PasswdCommand {
    fn rotate(&self, cfg: &CredentialConfigData) -> GenericErr {
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
        log::info!("Password successfully uploaded");
        Ok(())
    }
}