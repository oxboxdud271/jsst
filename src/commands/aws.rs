use crate::args::GlobalOpts;
use crate::commands::base::{JSSTCommand};
use crate::vault::VaultClient;
use clap::{Args, Subcommand};


#[derive(Args)]
pub struct SetupArgs {
    #[arg(short, long)]
    /// Force re-setup
    pub force: bool,

    #[arg(short, long)]
    /// Vault token with sufficient permission to create AWS Vault role
    pub token: String
}

#[derive(Subcommand)]
pub enum CliCommandEnum {
    /// Setup AWS Role in Vault
    Setup(SetupArgs),
    /// Retrieve Temporary AWS Credentials
    Retrieve,
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
    fn execute(commands: AWSCommandStruct, opts: GlobalOpts) -> Self
    {
        let cmd = Self { commands, opts };
        Self::command_wrapper(
            &cmd,
            &cmd.opts.output,
            &cmd.opts.server,
            |a, b| {
                match &a.commands.command {
                    CliCommandEnum::Setup(args) => Self::setup(a, b, &args),
                    CliCommandEnum::Retrieve => Self::retrieve(a, b)
                }
            }
        );
        cmd
    }
}

impl AWSCommand {
    fn setup(&self, client: &VaultClient, args: &SetupArgs) {}

    fn retrieve(&self, client: &VaultClient) {}
}
