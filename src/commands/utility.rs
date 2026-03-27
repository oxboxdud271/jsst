use clap::{Args, Subcommand};
use crate::args::GlobalOpts;
use crate::commands::base::{CredentialConfigData, JSSTCommand};
use crate::util::GenericErr;

#[derive(Subcommand)]
pub enum CliCommandEnum {
    /// Retrieve Vault Data Key
    DataKey,
    /// Setup Environment variables for Restic
    Restic
}

#[derive(Args)]
pub struct UtilityCommandStruct {
    #[command(subcommand)]
    pub command: CliCommandEnum,
}

pub struct UtilityCommand {
    pub commands: UtilityCommandStruct,
    pub opts: GlobalOpts,
}

impl JSSTCommand<UtilityCommandStruct> for UtilityCommand {
    fn execute(commands: UtilityCommandStruct, opts: GlobalOpts) -> GenericErr {
        let cmd = Self { commands, opts };
        Ok(Self::command_wrapper(
            &cmd,
            &cmd.opts,
            |cmd, cfg| {
                Ok(match &cmd.commands.command {
                    CliCommandEnum::DataKey => Self::get_data_key(cmd, cfg)?,
                    CliCommandEnum::Restic => todo!()
                })
            }
        )?)
    }
}
impl UtilityCommand {
    fn get_data_key(&self, cfg: &CredentialConfigData) -> GenericErr {
        let client = Self::login_to_vault(&self.opts.server, &cfg)?;

        Ok(())
    }
}