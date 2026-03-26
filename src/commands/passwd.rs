use clap::{Args, Subcommand};
use crate::args::GlobalOpts;
use crate::commands::base::JSSTCommand;

#[derive(Subcommand)]
pub enum CliCommandEnum {
    /// Setup KV in Vault
    Setup,
    /// Rotate Password
    Rotate
}

#[derive(Args)]
pub struct PasswdCommandStruct {
    #[command(subcommand)]
    pub command: CliCommandEnum,
}

pub struct PasswdCommand {
    pub commands: PasswdCommandStruct,
    pub opts: GlobalOpts,
}

impl JSSTCommand<PasswdCommandStruct> for PasswdCommand {
    fn execute(commands: PasswdCommandStruct, opts: GlobalOpts) -> Self
    {
        let cmd = Self { commands, opts };
        Self::command_wrapper(
            &cmd,
            &cmd.opts,
            |cmd, cfg| {
            }
        );
        cmd
    }
}