use std::process::ExitCode;

use clap::{Parser, Subcommand};
use lforge_core::BuildInfo;

#[derive(Parser)]
#[command(
    name = "lforge",
    version,
    about = "Leonida Forge command-line interface"
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
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Info { json } => info(json),
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
