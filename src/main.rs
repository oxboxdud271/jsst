use clap::Parser;
use std::fs;
use std::path::Path;
use crate::commands::base::JSSTCommand;

pub mod args;
pub mod commands;
pub mod util;
mod vault;

fn main() {
    let cli = args::Cli::parse();
    let output_dir = Path::new(&cli.global_opts.output);
    if !output_dir.exists() {
        println!("Output Directory does not exists. Creating..");
        match fs::create_dir_all(output_dir) {
            Ok(_) => {
                println!("Output Directory Created.")
            }
            Err(e) => {
                println!("Failed to create output directory: [{}]", e.to_string())
            }
        }
    }

    match cli.command {
        args::PrimaryCommandEnum::Credentials(commands) => {
            commands::credentials::CredentialsCommand::execute(commands, cli.global_opts);
        }
        args::PrimaryCommandEnum::GPGKey { .. } => {}
        args::PrimaryCommandEnum::Crypt { .. } => {}
        args::PrimaryCommandEnum::SSH { .. } => {}
        args::PrimaryCommandEnum::Password { .. } => {},
        args::PrimaryCommandEnum::AWS(commands) => {
            commands::aws::AWSCommand::execute(commands, cli.global_opts);
        }
    }
}
