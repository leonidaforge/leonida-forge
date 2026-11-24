mod archive;
mod binary;
mod metadata;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use lforge_core::BuildInfo;

#[derive(Parser)]
#[command(
    name = "lforge",
    version,
    about = "Leonida Forge command-line interface",
    after_help = "Exit codes: 0 on success, 1 when a command fails, 2 for invalid usage."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print application and build information
    Info {
        /// Print as JSON
        #[arg(long)]
        json: bool,
    },
    /// Inspect binary files without modifying them
    #[command(subcommand)]
    Binary(binary::Command),
    /// List what can be recovered from RPF9 archives, without modifying them
    #[command(subcommand)]
    Archive(archive::Command),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Info { json } => info(json),
        Command::Binary(command) => report(binary::run(command)),
        Command::Archive(command) => report(archive::run(command)),
    }
}

fn report(result: Result<(), String>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn info(json: bool) -> ExitCode {
    let info = BuildInfo::current();
    if !json {
        println!("{} {}", info.name, info.version);
        println!("os:      {}", info.os);
        println!("arch:    {}", info.arch);
        println!("profile: {}", info.profile);
        return ExitCode::SUCCESS;
    }
    match serde_json::to_string_pretty(&info) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: failed to serialize build information: {err}");
            ExitCode::FAILURE
        }
    }
}
