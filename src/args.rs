use crate::commands::aws::AWSCommandStruct;
use crate::commands::credentials::CredentialsCommandStruct;
use crate::commands::passwd::PasswdCommandStruct;
use clap::{Args, Parser, Subcommand};
use crate::commands::utility::UtilityCommandStruct;

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: PrimaryCommandEnum,

    #[clap(flatten)]
    pub global_opts: GlobalOpts,
}

#[derive(Args)]
pub struct GlobalOpts {
    /// JSST Output Directory
    #[arg(short, long, default_value = "/var/lib/jdn/jsst")]
    pub output: String,

    /// Vault Server
    #[arg(short, long, default_value = "https://vault.jdn-lab.com")]
    pub server: String,

    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[arg(short, long, global = true)]
    pub quiet: bool,

    #[arg(short, long)]
    /// Provide a token. This will bypass the client auth process.
    pub token: Option<String>,
}

#[derive(Subcommand)]
pub enum BaseSubCommandEnum {
    /// Refresh
    Refresh,
    /// Display Current Status
    Show,
}

#[derive(Subcommand)]
pub enum PrimaryCommandEnum {
    /// Manage the Vault Credentials
    Credentials(CredentialsCommandStruct),
    /// Manage SSH Key
    SSH {
        #[command(subcommand)]
        command: BaseSubCommandEnum,
    },
    /// Manage Local User Passwords
    Password(PasswdCommandStruct),
    /// Manage AWS Credentials
    AWS(AWSCommandStruct),
    /// Utility Functions
    Utility(UtilityCommandStruct)
}
