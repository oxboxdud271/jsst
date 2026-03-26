use crate::commands::base::JSSTCommand;
use crate::logging::logger_init;
use clap::Parser;
use std::fs;
use std::path::Path;

pub mod args;
pub mod commands;
pub mod util;
mod vault;
pub mod logging;

fn main() {
    let cli = args::Cli::parse();
    let output_dir = Path::new(&cli.global_opts.output);
    if !output_dir.exists() {
        log::info!("Output Directory does not exists. Creating..");
        match fs::create_dir_all(output_dir) {
            Ok(_) => {
                log::info!("Output Directory Created.")
            }
            Err(e) => {
                log::error!("Failed to create output directory: [{}]", e.to_string());
                return;
            }
        }
    }

    let mut max_log = log::LevelFilter::Info;
    if cli.global_opts.quiet {
        max_log = log::LevelFilter::Off;
    } else if cli.global_opts.verbose {
        max_log = log::LevelFilter::Debug;
    }

    match logger_init(max_log) {
        Ok(_) => (),
        Err(e) => {
            log::error!("Logger initialization failed with {:?}", e);
            return;
        }
    };

    match cli.command {
        args::PrimaryCommandEnum::Credentials(commands) => {
            commands::credentials::CredentialsCommand::execute(commands, cli.global_opts);
        }
        args::PrimaryCommandEnum::GPGKey { .. } => {}
        args::PrimaryCommandEnum::Crypt { .. } => {}
        args::PrimaryCommandEnum::SSH { .. } => {}
        args::PrimaryCommandEnum::Password { .. } => {}
        args::PrimaryCommandEnum::AWS(commands) => {
            commands::aws::AWSCommand::execute(commands, cli.global_opts);
        }
    }
}
