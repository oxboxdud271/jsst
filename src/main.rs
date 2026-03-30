use std::error::Error;
use crate::commands::base::JSSTCommand;
use crate::logging::logger_init;
use clap::Parser;
use std::fs;
use std::path::Path;
use std::process::ExitCode;
use crate::args::Cli;

pub mod args;
pub mod commands;
pub mod util;
mod vault;
pub mod logging;


fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    Ok(match cli.command {
        args::PrimaryCommandEnum::Credentials(c) => {
            commands::credentials::CredentialsCommand::execute(c, cli.global_opts)?
        }
        args::PrimaryCommandEnum::SSH { .. } => {}
        args::PrimaryCommandEnum::Password(c) => {
            commands::passwd::PasswdCommand::execute(c, cli.global_opts)?
        }
        args::PrimaryCommandEnum::AWS(c) => {
            commands::aws::AWSCommand::execute(c, cli.global_opts)?
        }
        args::PrimaryCommandEnum::Utility(c) => {
            commands::utility::UtilityCommand::execute(c, cli.global_opts)?
        }
        args::PrimaryCommandEnum::Backup(c) => {
            commands::backup::BackupCommand::execute(c, cli.global_opts)?
        }
    })
}

fn main() -> ExitCode {
    let cli = args::Cli::parse();

    let mut max_log = log::LevelFilter::Info;
    if cli.global_opts.quiet {
        max_log = log::LevelFilter::Off;
    }
    if cli.global_opts.verbose {
        max_log = log::LevelFilter::Debug;
    }

    match logger_init(max_log) {
        Ok(_) => (),
        Err(e) => {
            log::error!("Logger initialization failed with {:?}", e);
            return ExitCode::FAILURE;
        }
    };

    let output_dir = Path::new(&cli.global_opts.output);
    if !output_dir.exists() {
        log::info!("Output Directory does not exists. Creating..");
        match fs::create_dir_all(output_dir) {
            Ok(_) => {
                log::info!("Output Directory Created.")
            }
            Err(e) => {
                log::error!("Failed to create output directory: [{}]", e.to_string());
                return ExitCode::FAILURE;
            }
        }
    }

    match run(cli) {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            log::error!("{}", e);
            ExitCode::FAILURE
        }
    }
}
