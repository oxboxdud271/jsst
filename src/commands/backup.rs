use clap::{Args, Subcommand};
use crate::args::GlobalOpts;
use crate::commands::base::{CredentialConfigData, JSSTCommand};
use crate::util::GenericErr;

#[derive(Subcommand)]
pub enum CliCommandEnum {
    /// Backup JDN Directory
    JDN,
    /// Backup LUKS Header
    LUKS
}

#[derive(Args)]
pub struct BackupCommandStruct {
    #[command(subcommand)]
    pub command: CliCommandEnum,

    #[arg(long, default_value = "server-admin")]
    username: String,
}

pub struct BackupCommand {
    pub cli: BackupCommandStruct,
    pub opts: GlobalOpts,
}

impl JSSTCommand<BackupCommandStruct> for BackupCommand {
    fn execute(commands: BackupCommandStruct, opts: GlobalOpts) -> GenericErr {
        let cmd = Self { cli: commands, opts };
        Ok(Self::command_wrapper(
            &cmd,
            &cmd.opts,
            |cmd, cfg| {
                match &cmd.cli.command {
                    CliCommandEnum::JDN => Self::backup_jdn(&cmd, &cfg),
                    CliCommandEnum::LUKS => todo!()
                }
            }
        )?)
    }
}

impl BackupCommand {
    fn backup_jdn(&self, cfg: &CredentialConfigData) -> GenericErr {
        Ok(())
    }
}