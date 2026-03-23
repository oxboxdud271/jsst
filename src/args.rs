use clap::{Parser, Subcommand, Args};

use crate::commands::credentials::CredentialsCommandStruct;

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
    #[arg(short, long, default_value = "https://secrets.jdn-lab.com")]
    pub server: String,

    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[arg(short, long, global = true)]
    pub quiet: bool,
}


#[derive(Subcommand)]
pub enum BaseSubCommandEnum {
    /// Refresh
    Refresh,
    /// Display Current Status
    Show
}

#[derive(Subcommand)]
pub enum PrimaryCommandEnum {
    /// Manage the Vault Credentials
    Credentials(CredentialsCommandStruct),
    /// Manage SSH Key
    SSH{
        #[command(subcommand)]
        command: BaseSubCommandEnum,
    },
    /// Manage Local GPG Encryption Key
    GPGKey{
        #[command(subcommand)]
        command: BaseSubCommandEnum,
    },
    /// Manage Local User Passwords
    Password{
        #[command(subcommand)]
        command: BaseSubCommandEnum,
    },
    /// Manage LUKS
    Crypt{
        #[command(subcommand)]
        command: BaseSubCommandEnum,
    }
}