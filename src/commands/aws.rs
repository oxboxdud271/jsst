use clap::{Args, Subcommand};
use crate::args::GlobalOpts;
use crate::commands::base::{JSSTCommand};
use crate::vault::VaultClient;

#[derive(Subcommand)]
pub enum CliCommandEnum {
    /// Setup AWS Role in Vault
    Setup,
    /// Retrieve Temporary AWS Credentials
    Retrieve
}

#[derive(Args)]
pub struct AWSCommandStruct {
    #[command(subcommand)]
    pub command: CliCommandEnum,
}


pub struct AWSCommand {
    pub commands: AWSCommandStruct,
    pub opts: GlobalOpts,
}

impl JSSTCommand<AWSCommandStruct> for AWSCommand {
    fn execute(commands: AWSCommandStruct, opts: GlobalOpts) -> Self {
        let cmd = Self{commands, opts};
        Self::command_wrapper(
            &cmd,
            &cmd.opts.output,
            &cmd.opts.server,
            match &cmd.commands.command {
                CliCommandEnum::Setup => Self::setup,
                CliCommandEnum::Retrieve => Self::retrieve,
            }
        );
        cmd
    }
}

impl AWSCommand {
    fn setup(&self, client: &VaultClient) {}

    fn retrieve(&self, client: &VaultClient) {}
}