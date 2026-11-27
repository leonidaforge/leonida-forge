mod archive;
mod binary;
mod catalog;
mod census;
mod extract;
mod inspect;
mod inventory;
mod metadata;
mod names;
mod native;
mod nested;
mod output;
mod probe;
mod recover;
mod registry;
mod rows;
mod verify;

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
    /// Index native name hashes, harvest candidate names and export LUT files
    #[command(subcommand)]
    Names(names::Command),
    /// Extract catalog observations and validate publication packages
    #[command(subcommand)]
    Catalog(catalog::Command),
}

fn main() -> ExitCode {
    // The command tree is rebuilt on every run, and the argument parser needs
    // more stack than Windows gives the main thread once the subcommands add up.
    // Run the interface on a thread with a known stack instead of depending on
    // the size the linker happens to pick.
    const STACK: usize = 16 * 1024 * 1024;
    match std::thread::Builder::new()
        .name("lforge".to_string())
        .stack_size(STACK)
        .spawn(run)
    {
        Ok(handle) => handle
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
        Err(err) => {
            eprintln!("error: cannot start the command thread: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Info { json } => info(json),
        Command::Binary(command) => report(binary::run(command)),
        Command::Archive(command) => report(archive::run(command)),
        Command::Names(command) => report(names::run(command)),
        Command::Catalog(command) => report(catalog::run(command)),
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
